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
)

// DeepCopy returns a copy of the user that shares no map, slice or pointer
// with the original, so decoding a request body into the copy leaves the
// original untouched. Reference fields are cloned through their JSON form,
// the representation the API and the database already use for them; fields
// tagged json:"-" keep the plain copy because JSON decoding never reaches them.
func (user *User) DeepCopy() (*User, error) {
	if user == nil {
		return nil, nil
	}

	clone := *user
	src := reflect.ValueOf(user).Elem()
	dst := reflect.ValueOf(&clone).Elem()
	for i := 0; i < src.NumField(); i++ {
		field := src.Type().Field(i)
		if !field.IsExported() || field.Tag.Get("json") == "-" || !holdsReference(field.Type) {
			continue
		}

		data, err := json.Marshal(src.Field(i).Interface())
		if err != nil {
			return nil, err
		}

		dst.Field(i).SetZero()
		err = json.Unmarshal(data, dst.Field(i).Addr().Interface())
		if err != nil {
			return nil, err
		}
	}

	return &clone, nil
}

// holdsReference reports whether a value of type t can share memory with its shallow copy.
func holdsReference(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Map, reflect.Slice, reflect.Pointer, reflect.Interface, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return true
	case reflect.Array:
		return holdsReference(t.Elem())
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if holdsReference(t.Field(i).Type) {
				return true
			}
		}
	}
	return false
}
