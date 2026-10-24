// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/casdoor/casdoor/util"
)

type OriginalUser = User

func (syncer *Syncer) getOriginalUsers() ([]*OriginalUser, error) {
	provider := GetSyncerProvider(syncer)
	return provider.GetOriginalUsers()
}

func (syncer *Syncer) addUser(user *OriginalUser) (bool, error) {
	provider := GetSyncerProvider(syncer)
	return provider.AddUser(user)
}

func (syncer *Syncer) getCasdoorColumns() []string {
	res := []string{}
	for _, tableColumn := range syncer.TableColumns {
		if tableColumn.CasdoorName != "Id" {
			v := util.CamelToSnakeCase(tableColumn.CasdoorName)
			// CasdoorName is org-admin controlled and these values become column names in
			// an UPDATE SET clause, so drop anything that is not a plain SQL identifier.
			if !util.FilterSQLIdentifier(v) {
				continue
			}
			res = append(res, v)
		}
	}
	return res
}

func (syncer *Syncer) updateUser(user *OriginalUser) (bool, error) {
	provider := GetSyncerProvider(syncer)
	return provider.UpdateUser(user)
}

func (syncer *Syncer) updateUserForOriginalFields(user *User, key string) (bool, error) {
	var err error
	oldUser := User{}

	// key is the snake_cased CasdoorName of the syncer's key column, which an org admin
	// controls, and it is concatenated into the WHERE clause below, so reject any value
	// that is not a plain SQL identifier to keep it from injecting SQL into Casdoor's DB.
	if !util.FilterSQLIdentifier(key) {
		return false, fmt.Errorf("object.updateUserForOriginalFields() error: invalid key field: %s", key)
	}

	existed, err := ormer.Engine.Where(key+" = ? and owner = ?", syncer.getUserValue(user, key), user.Owner).Get(&oldUser)
	if err != nil {
		return false, err
	}
	if !existed {
		return false, nil
	}

	if user.Avatar != oldUser.Avatar && user.Avatar != "" {
		user.PermanentAvatar, err = getPermanentAvatarUrl(user.Owner, user.Name, user.Avatar, true)
		if err != nil {
			return false, err
		}
	}

	columns := syncer.getCasdoorColumns()
	columns = append(columns, "affiliation", "hash", "pre_hash")

	// Skip password-related columns when the incoming user has no password data.
	// API-based syncers (DingTalk, WeCom, Lark, etc.) do not provide passwords,
	// so updating these columns would wipe out locally set passwords.
	if user.Password == "" {
		filtered := make([]string, 0, len(columns))
		for _, col := range columns {
			if col != "password" && col != "password_salt" && col != "password_type" {
				filtered = append(filtered, col)
			}
		}
		columns = filtered
	}

	// Add provider-specific field for API-based syncers to enable login binding
	// This allows synced users to login via their provider accounts
	switch syncer.Type {
	case "WeCom":
		columns = append(columns, "wecom")
	case "DingTalk":
		columns = append(columns, "dingtalk")
	case "Lark":
		columns = append(columns, "lark", "groups")
		user.Groups = mergeLarkDepartmentGroups(oldUser.Groups, user.Groups)
	}

	// The group APIs read memberships from the user enforcer, not from the groups column. It is
	// updated before the row so that a failure leaves the user to be retried by the next run, except
	// on a rename, which waits for the row so that a name clash cannot rewrite another user's bindings.
	isRenamed := syncer.Type == "Lark" && util.InSlice(columns, "name") && user.Name != oldUser.Name
	if syncer.Type == "Lark" && !isRenamed {
		err = updateSyncedUserGroupBindings(&oldUser, user, false)
		if err != nil {
			return false, err
		}
	}

	affected, err := ormer.Engine.Where(key+" = ? and owner = ?", syncer.getUserValue(&oldUser, key), oldUser.Owner).Cols(columns...).Update(user)
	if err != nil {
		return false, err
	}

	if isRenamed && affected != 0 {
		err = updateSyncedUserGroupBindings(&oldUser, user, true)
		if err != nil {
			return false, err
		}
	}

	return affected != 0, nil
}

func updateSyncedUserGroupBindings(oldUser *User, user *User, isRenamed bool) error {
	oldId := oldUser.GetId()
	newId := oldId
	if isRenamed {
		newId = util.GetId(oldUser.Owner, user.Name)
	}

	if newId == oldId && isSameGroupSet(oldUser.Groups, user.Groups) {
		return nil
	}

	if newId != oldId {
		_, err := userEnforcer.DeleteGroupsForUser(oldId)
		if err != nil {
			return err
		}
	}

	_, err := userEnforcer.UpdateGroupsForUser(newId, user.Groups)
	return err
}

func isSameGroupSet(a []string, b []string) bool {
	a = slices.Compact(slices.Sorted(slices.Values(a)))
	b = slices.Compact(slices.Sorted(slices.Values(b)))
	return slices.Equal(a, b)
}

func (syncer *Syncer) calculateHash(user *OriginalUser) string {
	values := []string{}
	m := syncer.getMapFromOriginalUser(user)
	for _, tableColumn := range syncer.TableColumns {
		if tableColumn.IsHashed {
			values = append(values, m[tableColumn.Name])
		}
	}

	// Lark department moves must change the hash; users without departments keep their old hash
	if syncer.Type == "Lark" && len(user.Groups) > 0 {
		groups := slices.Clone(user.Groups)
		slices.Sort(groups)
		values = append(values, strings.Join(groups, ","))
	}

	s := strings.Join(values, "|")
	return util.GetMd5Hash(s)
}

func (syncer *Syncer) initAdapter() error {
	provider := GetSyncerProvider(syncer)
	return provider.InitAdapter()
}

func RunSyncUsersJob() {
	syncers, err := GetSyncers("admin")
	if err != nil {
		fmt.Printf("RunSyncUsersJob() error: %s\n", err.Error())
		return
	}

	// A failing syncer must not stop the others; its error is already in its error text
	for _, syncer := range syncers {
		err = addSyncerJob(syncer)
		if err != nil {
			fmt.Printf("RunSyncUsersJob() failed to start syncer [%s]: %s\n", syncer.GetId(), err.Error())
		}
	}

	time.Sleep(time.Duration(1<<63 - 1))
}
