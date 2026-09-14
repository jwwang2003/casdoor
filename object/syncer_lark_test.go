// Copyright 2026 The Casdoor Authors. All Rights Reserved.
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
	"strings"
	"testing"

	"github.com/casdoor/casdoor/idp"
	"golang.org/x/oauth2"
)

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

	provider := &LarkSyncerProvider{Syncer: &Syncer{Host: server.URL, User: "app", Password: "secret"}}
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
			provider := &LarkSyncerProvider{Syncer: &Syncer{Host: server.URL, User: "app", Password: "secret"}}
			users, err := provider.GetOriginalUsers()
			if err == nil || !strings.Contains(err.Error(), "missing open_id") || users != nil {
				t.Fatalf("expected an error without partial users, got users=%v err=%v", users, err)
			}
		})
	}
}
