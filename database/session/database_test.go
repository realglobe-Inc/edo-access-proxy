// Copyright 2015 realglobe, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package session

import (
	"reflect"
	"testing"
	"time"
)

func testDb(t *testing.T, db Db) {
	if elem, err := db.GetByParams(test_acntTag, test_tokTag, test_toTa); err != nil {
		t.Fatal(err)
	} else if elem != nil {
		t.Fatal(elem)
	}

	exp := time.Now().Add(time.Second)
	elem := New(test_id, exp, test_acntTag, test_tokTag, test_toTa)
	saveExp := exp.Add(time.Minute)

	if err := db.Save(elem, saveExp); err != nil {
		t.Fatal(err)
	}

	elem2, err := db.GetByParams(elem.AccountTag(), elem.TokenTag(), elem.ToTa())
	if err != nil {
		t.Fatal(err)
	} else if elem2 == nil {
		t.Fatal("no element")
	} else if !reflect.DeepEqual(elem2, elem) {
		t.Error(elem2)
		t.Fatal(elem)
	}
}
