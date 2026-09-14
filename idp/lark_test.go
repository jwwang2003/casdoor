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

package idp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestLarkGetUserInfoRejectsInvalidIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"API error", http.StatusOK, `{"code":20001,"data":{"open_id":"ou-1"}}`},
		{"missing identity", http.StatusOK, `{"code":0,"data":{"user_id":"employee-1","email":"employee@example.com"}}`},
		{"HTTP error", http.StatusUnauthorized, `{"code":0,"data":{"open_id":"ou-1"}}`},
		{"invalid JSON", http.StatusOK, `not JSON`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()
			provider := NewLarkIdProvider("app", "secret", "https://sso.example.com/callback", false)
			provider.LarkDomain = server.URL
			provider.SetHttpClient(server.Client())
			token := (&oauth2.Token{AccessToken: "test-token"}).WithExtra(map[string]interface{}{"code": "test-code"})
			user, err := provider.GetUserInfo(token)
			if err == nil || user != nil {
				t.Fatalf("expected identity rejection, got user=%v err=%v", user, err)
			}
		})
	}
}

func TestLarkGetUserInfoRejectsMissingCode(t *testing.T) {
	provider := NewLarkIdProvider("app", "secret", "https://sso.example.com/callback", false)
	for _, token := range []*oauth2.Token{nil, {}, (&oauth2.Token{}).WithExtra(map[string]interface{}{"code": 123})} {
		user, err := provider.GetUserInfo(token)
		if err == nil || user != nil {
			t.Fatalf("expected invalid authorization rejection, got user=%v err=%v", user, err)
		}
	}
}
