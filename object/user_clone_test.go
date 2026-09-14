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
	"reflect"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

// partialUserUpdateBody is the body of POST /api/update-user?columns=properties
// that a non-admin could use to escalate before the permission check saw a change.
const partialUserUpdateBody = `{"properties":{"headplane_role":"admin"},"groups":["x","employees/b"]}`

func newDeepCopyTestUser() *User {
	return &User{
		Owner:               "employees",
		Name:                "alice",
		DisplayName:         "Alice",
		Balance:             1.5,
		IsAdmin:             true,
		Address:             []string{"line 1"},
		Addresses:           []*Address{{Tag: "home", City: "Oslo"}},
		WebauthnCredentials: []webauthn.Credential{{ID: []byte("credential"), PublicKey: []byte("key"), Authenticator: webauthn.Authenticator{AAGUID: []byte("aaguid"), SignCount: 3}}},
		RecoveryCodes:       []string{"code-1"},
		MultiFactorAuths:    []*MfaProps{{MfaType: "sms", Enabled: true, RecoveryCodes: []string{"code-1"}}},
		FaceIds:             []*FaceId{{Name: "face", FaceIdData: []float64{0.5, 1.25}}},
		Cart:                []ProductInfo{{Name: "product", Price: 2.5}},
		Properties:          map[string]string{"headplane_role": "member"},
		ThirdPartyLinks:     []*ThirdPartyLink{{ProviderName: "lark", ProviderId: "ou-1"}},
		Roles:               []*Role{{Owner: "employees", Name: "role", Users: []string{"employees/alice"}}},
		Permissions:         []*Permission{{Owner: "employees", Name: "permission", Actions: []string{"Read"}}},
		Groups:              []string{"employees/a", "employees/b"},
		ManagedAccounts:     []ManagedAccount{{Application: "app", Username: "alice"}},
		MfaAccounts:         []MfaAccount{{AccountName: "alice", Issuer: "casdoor"}},
		MfaItems:            []*MfaItem{{Name: "sms", Rule: "Optional"}},
		ApplicationScopes:   []ConsentRecord{{Application: "app", GrantedScopes: []string{"openid"}}},
	}
}

func TestUserDeepCopyIsIndependent(t *testing.T) {
	original := newDeepCopyTestUser()
	clone, err := original.DeepCopy()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(clone, original) {
		t.Fatalf("clone differs from the original:\n%+v\n%+v", clone, original)
	}

	src := reflect.ValueOf(original).Elem()
	dst := reflect.ValueOf(clone).Elem()
	for i := 0; i < src.NumField(); i++ {
		field := src.Type().Field(i)
		if field.Tag.Get("json") == "-" && !reflect.DeepEqual(src.Field(i).Interface(), dst.Field(i).Interface()) {
			t.Errorf("field %s tagged json:\"-\" was not preserved", field.Name)
		}
		switch src.Field(i).Kind() {
		case reflect.Slice:
			if src.Field(i).Len() > 0 && src.Field(i).Pointer() == dst.Field(i).Pointer() {
				t.Errorf("field %s shares its backing array with the original", field.Name)
			}
		case reflect.Map, reflect.Pointer:
			if !src.Field(i).IsNil() && src.Field(i).Pointer() == dst.Field(i).Pointer() {
				t.Errorf("field %s is shared with the original", field.Name)
			}
		}
	}

	clone.Properties["headplane_role"] = "admin"
	clone.Groups[0] = "x"
	clone.Address[0] = "line 2"
	clone.Addresses[0].City = "Bergen"
	clone.WebauthnCredentials[0].ID[0] = 'X'
	clone.RecoveryCodes[0] = "code-2"
	clone.MultiFactorAuths[0].RecoveryCodes[0] = "code-2"
	clone.FaceIds[0].FaceIdData[0] = 9
	clone.Cart[0].Name = "other"
	clone.ThirdPartyLinks[0].ProviderId = "ou-2"
	clone.Roles[0].Users[0] = "employees/bob"
	clone.Permissions[0].Actions[0] = "Write"
	clone.ManagedAccounts[0].Username = "bob"
	clone.MfaAccounts[0].Issuer = "other"
	clone.MfaItems[0].Rule = "Required"
	clone.ApplicationScopes[0].GrantedScopes[0] = "profile"
	if !reflect.DeepEqual(original, newDeepCopyTestUser()) {
		t.Fatalf("mutating the clone changed the original: %+v", original)
	}
}

func TestUserDeepCopyKeepsOriginalForPermissionCheck(t *testing.T) {
	original := newDeepCopyTestUser()
	merged, err := original.DeepCopy()
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(partialUserUpdateBody), merged); err != nil {
		t.Fatal(err)
	}

	if original.Properties["headplane_role"] != "member" || !reflect.DeepEqual(original.Groups, []string{"employees/a", "employees/b"}) {
		t.Fatalf("partial update leaked into the original: properties=%v groups=%v", original.Properties, original.Groups)
	}
	if merged.Properties["headplane_role"] != "admin" || !reflect.DeepEqual(merged.Groups, []string{"x", "employees/b"}) {
		t.Fatalf("partial update was not applied to the copy: properties=%v groups=%v", merged.Properties, merged.Groups)
	}
	if merged.Name != original.Name || merged.DisplayName != original.DisplayName || merged.Address[0] != original.Address[0] {
		t.Fatalf("fields absent from the body were not carried over: %+v", merged)
	}
}

// TestUserDeepCopyControlShallowCopyAliases documents the defect DeepCopy fixes:
// encoding/json keeps entries of an existing map and reuses a slice's backing
// array, so decoding into a struct copy rewrites the original as well.
func TestUserDeepCopyControlShallowCopyAliases(t *testing.T) {
	original := newDeepCopyTestUser()
	shallow := *original
	if err := json.Unmarshal([]byte(partialUserUpdateBody), &shallow); err != nil {
		t.Fatal(err)
	}
	if original.Properties["headplane_role"] != "admin" || original.Groups[0] != "x" {
		t.Fatalf("expected the shallow copy to alias the original: properties=%v groups=%v", original.Properties, original.Groups)
	}
}
