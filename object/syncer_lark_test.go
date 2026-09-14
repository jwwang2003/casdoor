// Copyright 2025 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/idp"
	"golang.org/x/oauth2"
)

func TestLarkUserToOriginalUserDefaultEmail(t *testing.T) {
	provider := &LarkSyncerProvider{Syncer: &Syncer{}}

	user := provider.larkUserToOriginalUser(&LarkUser{
		UserId:          "u-1",
		Name:            "Alice",
		Email:           "alice@example.com",
		EnterpriseEmail: "alice@corp.example.com",
	})

	if user.Email != "alice@example.com" {
		t.Fatalf("default mapping must use email, got %q", user.Email)
	}
}

func TestLarkUserToOriginalUserEnterpriseEmail(t *testing.T) {
	provider := &LarkSyncerProvider{Syncer: &Syncer{
		TableColumns: []*TableColumn{
			{Name: "enterprise_email", CasdoorName: "Email"},
		},
	}}

	user := provider.larkUserToOriginalUser(&LarkUser{
		UserId:          "u-1",
		Name:            "Alice",
		Email:           "alice@example.com",
		EnterpriseEmail: "alice@corp.example.com",
	})

	if user.Email != "alice@corp.example.com" {
		t.Fatalf("enterprise_email mapping must override email, got %q", user.Email)
	}
	// Fields not listed in TableColumns keep their default mapping.
	if user.Name != "u-1" || user.DisplayName != "Alice" {
		t.Fatalf("default fields must be preserved, got name=%q displayName=%q", user.Name, user.DisplayName)
	}
}

func TestLarkUserToOriginalUserUnknownColumnIsIgnored(t *testing.T) {
	provider := &LarkSyncerProvider{Syncer: &Syncer{
		TableColumns: []*TableColumn{
			{Name: "enterprise_mail", CasdoorName: "Email"}, // typo on purpose
		},
	}}

	user := provider.larkUserToOriginalUser(&LarkUser{
		UserId:          "u-1",
		Name:            "Alice",
		Email:           "alice@example.com",
		EnterpriseEmail: "alice@corp.example.com",
	})

	if user.Email != "alice@example.com" {
		t.Fatalf("unknown column must not overwrite the field, got %q", user.Email)
	}
}

func TestLarkUserFieldValue(t *testing.T) {
	provider := &LarkSyncerProvider{Syncer: &Syncer{}}
	u := &LarkUser{UserId: "u-1", EnterpriseEmail: "alice@corp.example.com"}

	if v, ok := provider.getLarkUserFieldValue(u, "enterprise_email"); !ok || v != "alice@corp.example.com" {
		t.Fatalf("enterprise_email = %q, %v", v, ok)
	}
	if _, ok := provider.getLarkUserFieldValue(u, "enterprise_mail"); ok {
		t.Fatal("unknown field must return ok=false")
	}
}

func TestLarkSyncerOAuthIdentity(t *testing.T) {
	// A user in two departments must appear once. Distinct users without
	// user_id must remain distinct, and every imported binding must match login.
	users := []*LarkUser{
		{UserId: "employee-1", OpenId: "ou-1", Email: "personal@example.com", EnterpriseEmail: "work@example.com"},
		{UnionId: "on-2", OpenId: "ou-2", EnterpriseEmail: "second@example.com"},
		{OpenId: "ou-3", EnterpriseEmail: "third@example.com"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "tenant_access_token": "test-token"})
		case "/open-apis/contact/v3/departments":
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "data": map[string]interface{}{"items": []map[string]string{{"open_department_id": "od-1"}}}})
		case "/open-apis/contact/v3/users/find_by_department":
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Error("directory request did not use the app token")
			}
			items := users
			if r.URL.Query().Get("department_id") == "od-1" {
				items = users[:1]
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "data": map[string]interface{}{"items": items}})
		case "/open-apis/authen/v1/access_token":
			var body struct {
				Code string `json:"code"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			for _, user := range users {
				if user.OpenId == body.Code {
					json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "data": user})
					return
				}
			}
			http.Error(w, "unknown test identity", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := &LarkSyncerProvider{Syncer: &Syncer{Organization: "built-in", Host: server.URL, User: "app", Password: "secret"}}
	imported, err := provider.GetOriginalUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(imported) != len(users) {
		t.Fatalf("expected %d distinct users, got %d", len(users), len(imported))
	}
	login := idp.NewLarkIdProvider("app", "secret", "https://sso.example.com/callback", false)
	login.LarkDomain = server.URL
	login.SetHttpClient(server.Client())
	expectedIDs := map[string]string{"ou-1": "employee-1", "ou-2": "on-2", "ou-3": "ou-3"}
	for _, user := range imported {
		token := (&oauth2.Token{AccessToken: "test-token"}).WithExtra(map[string]interface{}{"code": user.Lark})
		identity, err := login.GetUserInfo(token)
		if err != nil {
			t.Fatal(err)
		}
		if user.Lark != identity.Id || user.Name != identity.Username || user.Id != expectedIDs[user.Lark] {
			t.Errorf("import and login disagree: imported ID=%q name=%q binding=%q, login ID=%q username=%q", user.Id, user.Name, user.Lark, identity.Id, identity.Username)
		}
		if user.Email == "" || user.Email != identity.Email {
			t.Errorf("directory email %q does not match login email %q", user.Email, identity.Email)
		}
	}
}

func TestLarkSyncerPaginationPreservesOpaqueCursor(t *testing.T) {
	// Feishu cursors are opaque and may contain reserved query characters.
	// Both department enumeration and user enumeration must preserve them.
	const cursor = "AQD9/Rn9e+next==&literal=%2B"
	requests := make(map[string][]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		if query.Get("department_id_type") != "open_department_id" || query.Get("user_id_type") != "open_id" {
			t.Error("expected explicit app-scoped user and department ID types")
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("expected authorization on every page")
		}
		pageToken := query.Get("page_token")
		requests[r.URL.Path] = append(requests[r.URL.Path], pageToken)
		if pageToken != "" && pageToken != cursor {
			t.Errorf("opaque cursor changed: got %q, expected %q", pageToken, cursor)
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		first := pageToken == ""
		var items interface{}
		switch r.URL.Path {
		case "/open-apis/contact/v3/departments":
			if query.Get("parent_department_id") != "0" || query.Get("fetch_child") != "true" {
				t.Error("expected recursive root department enumeration")
			}
			department := "od-2"
			if first {
				department = "od-1"
			}
			items = []map[string]string{{"open_department_id": department}}
		case "/open-apis/contact/v3/users/find_by_department":
			if query.Get("department_id") != "od-test" {
				t.Error("department changed while paginating")
			}
			identity := "ou-2"
			if first {
				identity = "ou-1"
			}
			items = []map[string]string{{"open_id": identity}}
		default:
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "data": map[string]interface{}{
			"items": items, "has_more": first, "page_token": cursor,
		}})
	}))
	defer server.Close()
	provider := &LarkSyncerProvider{Syncer: &Syncer{Organization: "built-in", Host: server.URL}}
	departments, err := provider.getLarkDepartments("test-token")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(departments, []string{"0", "od-1", "od-2"}) {
		t.Fatalf("missing department page: %v", departments)
	}
	users, err := provider.getLarkUsersFromDept("test-token", "od-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].OpenId != "ou-1" || users[1].OpenId != "ou-2" {
		t.Fatalf("missing user page: %v", users)
	}
	for path, cursors := range requests {
		if !slices.Equal(cursors, []string{"", cursor}) {
			t.Errorf("unexpected pages for %s: %v", path, cursors)
		}
	}
}

func TestLarkSyncerRejectsMissingOpenIDSnapshot(t *testing.T) {
	for _, invalid := range []string{`{"user_id":"employee-2"}`, `null`} {
		t.Run(invalid, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/open-apis/auth/v3/tenant_access_token/internal":
					w.Write([]byte(`{"code":0,"tenant_access_token":"test-token"}`))
				case "/open-apis/contact/v3/departments":
					w.Write([]byte(`{"code":0,"data":{"items":[]}}`))
				case "/open-apis/contact/v3/users/find_by_department":
					w.Write([]byte(`{"code":0,"data":{"items":[{"user_id":"employee-1","open_id":"ou-1"},` + invalid + `]}}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			provider := &LarkSyncerProvider{Syncer: &Syncer{Organization: "built-in", Host: server.URL, User: "app", Password: "secret"}}
			users, err := provider.GetOriginalUsers()
			if err == nil || !strings.Contains(err.Error(), "missing open_id") || users != nil {
				t.Fatalf("expected an error without partial users, got users=%v err=%v", users, err)
			}
		})
	}
}
