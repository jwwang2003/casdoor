package controllers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	beegocontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/xorm-io/xorm"
)

func enabledWebAuthnApplication(name, organization string) *object.Application {
	return &object.Application{Owner: "admin", Name: name, ClientId: name, Organization: organization,
		SigninMethods: []*object.SigninMethod{{Name: "WebAuthn", Rule: "None"}}}
}

func TestWebAuthnPolicyBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		change  func(**object.User, **object.Application, **object.Application)
		allowed bool
	}{
		{"allowed employee", func(_ **object.User, _ **object.Application, _ **object.Application) {}, true},
		{"missing user", func(u **object.User, _ **object.Application, _ **object.Application) { *u = nil }, false},
		{"missing requested app", func(_ **object.User, a **object.Application, _ **object.Application) { *a = nil }, false},
		{"missing signup app", func(_ **object.User, _ **object.Application, s **object.Application) { *s = nil }, false},
		{"forbidden user", func(u **object.User, _ **object.Application, _ **object.Application) { (*u).IsForbidden = true }, false},
		{"deleted user", func(u **object.User, _ **object.Application, _ **object.Application) { (*u).IsDeleted = true }, false},
		{"requested app method disabled", func(_ **object.User, a **object.Application, _ **object.Application) { (*a).SigninMethods = nil }, false},
		{"signup method disabled cannot bypass through shared builtin", func(_ **object.User, a **object.Application, s **object.Application) {
			(*s).SigninMethods = nil
			(*a).Organization = "built-in"
			(*a).IsShared = true
		}, false},
		{"requested app hidden", func(_ **object.User, a **object.Application, _ **object.Application) {
			(*a).SigninMethods[0].Rule = "Hide password"
		}, false},
		{"requested app disabled", func(_ **object.User, a **object.Application, _ **object.Application) { (*a).DisableSignin = true }, false},
		{"signup app disabled", func(_ **object.User, _ **object.Application, s **object.Application) { (*s).DisableSignin = true }, false},
		{"requested organization disabled", func(_ **object.User, a **object.Application, _ **object.Application) {
			(*a).OrganizationObj = &object.Organization{DisableSignin: true}
		}, false},
		{"signup organization disabled", func(_ **object.User, _ **object.Application, s **object.Application) {
			(*s).OrganizationObj = &object.Organization{DisableSignin: true}
		}, false},
		{"cross organization requested app", func(_ **object.User, a **object.Application, _ **object.Application) { (*a).Organization = "other" }, false},
		{"cross organization signup app", func(_ **object.User, _ **object.Application, s **object.Application) { (*s).Organization = "other" }, false},
		{"allowed shared app with enabled signup", func(_ **object.User, a **object.Application, _ **object.Application) {
			(*a).Organization = "built-in"
			(*a).IsShared = true
		}, true},
		{"allowed builtin administrator", func(u **object.User, a **object.Application, s **object.Application) {
			(*u).Owner = "built-in"
			(*u).IsAdmin = true
			(*a).Organization = "built-in"
			(*s).Organization = "built-in"
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &object.User{Owner: "employees", Name: "alice"}
			a, s := enabledWebAuthnApplication("target", "employees"), enabledWebAuthnApplication("signup", "employees")
			tt.change(&u, &a, &s)
			if err := checkWebAuthnPolicy(u, a, s); (err == nil) != tt.allowed {
				t.Fatalf("policy error = %v, allowed = %v", err, tt.allowed)
			}
		})
	}
}

// Captures every write, not just the final state: a handler that briefly creates
// an authenticated session and later deletes it must still fail these tests.
type webAuthnTestSession struct {
	values         map[interface{}]interface{}
	usernameWrites int
}

func (s *webAuthnTestSession) Set(_ context.Context, k, v interface{}) error {
	s.values[k] = v
	if k == "username" {
		s.usernameWrites++
	}
	return nil
}
func (s *webAuthnTestSession) Get(_ context.Context, k interface{}) interface{} { return s.values[k] }
func (s *webAuthnTestSession) Delete(_ context.Context, k interface{}) error {
	delete(s.values, k)
	return nil
}
func (s *webAuthnTestSession) SessionID(context.Context) string                             { return "synthetic-session" }
func (s *webAuthnTestSession) SessionReleaseIfPresent(context.Context, http.ResponseWriter) {}
func (s *webAuthnTestSession) SessionRelease(context.Context, http.ResponseWriter)          {}
func (s *webAuthnTestSession) Flush(context.Context) error {
	s.values = map[interface{}]interface{}{}
	return nil
}

func webAuthnController(request *http.Request, body []byte, session *webAuthnTestSession) (*ApiController, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx := beegocontext.NewContext()
	ctx.Reset(recorder, request)
	ctx.Input.RequestBody = body
	ctx.Input.CruSession = session
	c := &ApiController{}
	c.Init(ctx, "ApiController", "WebAuthnSigninFinish", c)
	return c, recorder
}

func webAuthnTestDatabase(t *testing.T) *xorm.Engine {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "webauthn.sqlite")
	for key, value := range map[string]string{"driverName": "sqlite", "dataSourceName": dsn, "dbName": "", "tableNamePrefix": "", "origin": "https://webauthn.invalid", "appname": "WebAuthn regression", "enableErrorMask2": "false"} {
		t.Setenv(key, value)
	}
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if err = engine.Sync2(new(object.User), new(object.Application), new(object.Organization), new(object.Session),
		new(object.ThirdPartyLink), new(object.Provider), new(object.Permission), new(object.Role), new(object.Group), new(object.Syncer)); err != nil {
		t.Fatal(err)
	}
	object.InitAdapter()
	for _, name := range []string{"employees", "built-in", "other"} {
		if _, err = engine.Insert(&object.Organization{Owner: "admin", Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	return engine
}

func syntheticWebAuthnAssertion(t *testing.T, user *object.User, discoverable bool) ([]byte, webauthn.SessionData) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := cbor.Marshal(map[int]interface{}{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	credentialID := make([]byte, 32)
	if _, err = rand.Read(credentialID); err != nil {
		t.Fatal(err)
	}
	user.WebauthnCredentials = []webauthn.Credential{{ID: credentialID, PublicKey: pub}}
	wa, err := object.GetWebAuthnObject("webauthn.invalid")
	if err != nil {
		t.Fatal(err)
	}
	var session *webauthn.SessionData
	if discoverable {
		_, session, err = wa.BeginDiscoverableLogin()
	} else {
		_, session, err = wa.BeginLogin(user)
	}
	if err != nil {
		t.Fatal(err)
	}
	client, _ := json.Marshal(map[string]interface{}{"type": "webauthn.get", "challenge": session.Challenge, "origin": "https://webauthn.invalid"})
	rpHash, clientHash := sha256.Sum256([]byte("webauthn.invalid")), sha256.Sum256(client)
	auth := append(append([]byte{}, rpHash[:]...), byte(5), byte(0), byte(0), byte(0), byte(1))
	digest := sha256.Sum256(append(append([]byte{}, auth...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	body, _ := json.Marshal(map[string]interface{}{"id": encode(credentialID), "rawId": encode(credentialID), "type": "public-key", "response": map[string]string{"authenticatorData": encode(auth), "clientDataJSON": encode(client), "signature": encode(signature), "userHandle": encode(user.WebAuthnID())}})
	// Independently prove that the cryptographic assertion would succeed. A
	// rejection caused only by malformed WebAuthn data is not a policy test.
	request := httptest.NewRequest("POST", "https://webauthn.invalid/api/webauthn/signin/finish", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if discoverable {
		_, err = wa.FinishDiscoverableLogin(func(_, _ []byte) (webauthn.User, error) { return user, nil }, *session, request)
	} else {
		_, err = wa.FinishLogin(user, *session, request)
	}
	if err != nil {
		t.Fatalf("synthetic assertion is not valid: %v", err)
	}
	return body, *session
}

func TestWebAuthnRejectedAssertionsNeverCreateSession(t *testing.T) {
	engine := webAuthnTestDatabase(t)
	tests := []struct {
		name        string
		change      func(*object.User, *object.Application, *object.Application)
		query       string
		missingUser bool
	}{
		{"disabled requested method", func(_ *object.User, a, _ *object.Application) {
			a.SigninMethods = []*object.SigninMethod{{Name: "Password", Rule: "All"}}
		}, "?responseType=code&clientId=target", false},
		{"disabled signup via shared builtin", func(_ *object.User, a, s *object.Application) {
			s.SigninMethods = []*object.SigninMethod{{Name: "Face ID", Rule: "Hide password"}}
			a.Organization = "built-in"
			a.IsShared = true
		}, "?responseType=code&clientId=target", false},
		{"forbidden user", func(u *object.User, _, _ *object.Application) { u.IsForbidden = true }, "", false},
		{"deleted user", func(u *object.User, _, _ *object.Application) { u.IsDeleted = true }, "", false},
		{"missing signup application", func(u *object.User, _, _ *object.Application) { u.SignupApplication = "missing" }, "", false},
		{"missing requested application", func(_ *object.User, _, _ *object.Application) {}, "?responseType=code&clientId=missing", false},
		{"missing client for code", func(_ *object.User, _, _ *object.Application) {}, "?responseType=code", false},
		{"cross organization target", func(_ *object.User, a, _ *object.Application) { a.Organization = "other" }, "?responseType=code&clientId=target", false},
		{"application tag exclusion", func(u *object.User, a, _ *object.Application) {
			u.Tag = "employee"
			a.Tags = []string{"approved-pilot"}
		}, "?responseType=code&clientId=target", false},
		{"unknown credential owner", func(_ *object.User, _, _ *object.Application) {}, "", true},
	}
	for _, discoverable := range []bool{false, true} {
		for _, tt := range tests {
			name := "named/"
			if discoverable {
				name = "discoverable/"
			}
			t.Run(name+tt.name, func(t *testing.T) {
				for _, table := range []string{"user", "application"} {
					if _, err := engine.Exec("DELETE FROM " + table); err != nil {
						t.Fatal(err)
					}
				}
				u := &object.User{Owner: "employees", Name: "alice", SignupApplication: "signup"}
				a, s := enabledWebAuthnApplication("target", "employees"), enabledWebAuthnApplication("signup", "employees")
				tt.change(u, a, s)
				if tt.name == "application tag exclusion" {
					if err := checkWebAuthnPolicy(u, a, s); err != nil {
						t.Fatalf("tag denial must reach HandleLoggedIn after WebAuthn policy passes: %v", err)
					}
				}
				body, challenge := syntheticWebAuthnAssertion(t, u, discoverable)
				if !tt.missingUser {
					if _, err := engine.Insert(u); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := engine.Insert(a, s); err != nil {
					t.Fatal(err)
				}
				session := &webAuthnTestSession{values: map[interface{}]interface{}{"authentication": challenge}}
				request := httptest.NewRequest("POST", "https://webauthn.invalid/api/webauthn/signin/finish"+tt.query, bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				controller, recorder := webAuthnController(request, body, session)
				controller.WebAuthnSigninFinish()
				if session.usernameWrites != 0 || session.values["username"] != nil {
					t.Fatalf("rejected request created an authenticated session: writes=%d", session.usernameWrites)
				}
				var result Response
				if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
					t.Fatalf("invalid response: %v: %s", err, recorder.Body.String())
				}
				if result.Status != "error" {
					t.Fatalf("expected denied response, got %s", recorder.Body.String())
				}
				if tt.name == "application tag exclusion" && !strings.Contains(result.Msg, "not listed") {
					t.Fatalf("expected HandleLoggedIn tag denial, got %s", recorder.Body.String())
				}
				if strings.Contains(result.Msg, "SQL") || strings.Contains(result.Msg, "no such table") {
					t.Fatalf("fixture database failure is not policy evidence: %s", recorder.Body.String())
				}
			})
		}
	}
}

func TestWebAuthnDisabledRegistration(t *testing.T) {
	engine := webAuthnTestDatabase(t)
	u := &object.User{Owner: "employees", Name: "alice", SignupApplication: "signup"}
	app := enabledWebAuthnApplication("signup", "employees")
	app.SigninMethods = []*object.SigninMethod{{Name: "Face ID", Rule: "Hide password"}}
	if _, err := engine.Insert(u, app); err != nil {
		t.Fatal(err)
	}
	for _, finish := range []bool{false, true} {
		name := "begin"
		if finish {
			name = "finish"
		}
		t.Run(name, func(t *testing.T) {
			session := &webAuthnTestSession{values: map[interface{}]interface{}{"username": u.GetId()}}
			request := httptest.NewRequest("POST", "https://webauthn.invalid/api/webauthn/signup/"+name, nil)
			controller, recorder := webAuthnController(request, nil, session)
			if finish {
				controller.WebAuthnSignupFinish()
			} else {
				controller.WebAuthnSignupBegin()
			}
			var result Response
			if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Status != "error" || !strings.Contains(result.Msg, "WebAuthn is not enabled") {
				t.Fatalf("must reject at application policy boundary: %s", recorder.Body.String())
			}
			if session.values["registration"] != nil {
				t.Fatal("disabled application issued a registration challenge")
			}
			stored := &object.User{Owner: u.Owner, Name: u.Name}
			if ok, err := engine.Get(stored); err != nil || !ok {
				t.Fatalf("reload user: found=%v err=%v", ok, err)
			}
			if len(stored.WebauthnCredentials) != 0 {
				t.Fatal("disabled registration persisted a credential")
			}
		})
	}
}

func TestWebAuthnAllowedAdministratorCreatesSession(t *testing.T) {
	engine := webAuthnTestDatabase(t)
	app := enabledWebAuthnApplication("signup", "built-in")
	if _, err := engine.Insert(app); err != nil {
		t.Fatal(err)
	}
	for _, discoverable := range []bool{false, true} {
		name := "named"
		if discoverable {
			name = "discoverable"
		}
		t.Run(name, func(t *testing.T) {
			u := &object.User{Owner: "built-in", Name: "admin-" + name, IsAdmin: true, SignupApplication: "signup"}
			body, challenge := syntheticWebAuthnAssertion(t, u, discoverable)
			if _, err := engine.Insert(u); err != nil {
				t.Fatal(err)
			}
			session := &webAuthnTestSession{values: map[interface{}]interface{}{"authentication": challenge}}
			request := httptest.NewRequest("POST", "https://webauthn.invalid/api/webauthn/signin/finish?responseType=login", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			controller, recorder := webAuthnController(request, body, session)
			controller.WebAuthnSigninFinish()
			var result Response
			if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
				t.Fatalf("invalid response: %v: %s", err, recorder.Body.String())
			}
			if result.Status != "ok" {
				t.Fatalf("allowed admin login failed: %s", recorder.Body.String())
			}
			if session.usernameWrites != 1 || session.values["username"] != u.GetId() {
				t.Fatalf("expected one successful session write, got %d", session.usernameWrites)
			}
		})
	}
}
