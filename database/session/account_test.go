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
	"encoding/json"
	"reflect"
	"testing"
)

func TestMainAccount(t *testing.T) {
	acnt := NewMainAccount(test_tokTag)

	if acnt.TokenTag() != test_tokTag {
		t.Error(acnt.TokenTag())
		t.Fatal(test_tokTag)
	} else if acnt.IdProvider() != "" {
		t.Error("ID provider is exist")
		t.Fatal(acnt.IdProvider())
	} else if acnt.Id() != "" {
		t.Error("account ID is exist")
		t.Fatal(acnt.Id())
	}
}

func TestSubAccount(t *testing.T) {
	acnt := NewSubAccount(test_idp, test_acntId)

	if acnt.TokenTag() != "" {
		t.Error("token tag is exist")
		t.Fatal(acnt.TokenTag())
	} else if acnt.IdProvider() != test_idp {
		t.Error(acnt.IdProvider())
		t.Fatal(test_idp)
	} else if acnt.Id() != test_acntId {
		t.Error(acnt.Id())
		t.Fatal(test_acntId)
	}
}

func TestMainAccountJson(t *testing.T) {
	acnt := NewMainAccount(test_tokTag)

	data, err := json.Marshal(acnt)
	if err != nil {
		t.Fatal(err)
	}

	var acnt2 Account
	if err := json.Unmarshal(data, &acnt2); err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(acnt, &acnt2) {
		t.Error(acnt)
		t.Fatal(&acnt2)
	}
}

func TestSubAccountJson(t *testing.T) {
	acnt := NewSubAccount(test_idp, test_acntId)

	data, err := json.Marshal(acnt)
	if err != nil {
		t.Fatal(err)
	}

	var acnt2 Account
	if err := json.Unmarshal(data, &acnt2); err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(acnt, &acnt2) {
		t.Error(acnt)
		t.Fatal(&acnt2)
	}
}
