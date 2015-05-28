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
	"time"
)

const (
	test_id      = "Xewtmrlnu5HVDzem5rmyGzoe2edQjI"
	test_acntTag = "UiK_r7aShx"
	test_tokTag  = "HcmmhWaXLE"
	test_toTa    = "https://ta.example.org"
)

func TestElement(t *testing.T) {
	exp := time.Now().Add(24 * time.Hour)
	elem := New(test_id, exp, test_acntTag, test_tokTag, test_toTa)

	if elem.Id() != test_id {
		t.Error(elem.Id())
		t.Fatal(test_id)
	} else if !elem.Expires().Equal(exp) {
		t.Error(elem.Expires())
		t.Fatal(exp)
	} else if elem.AccountTag() != test_acntTag {
		t.Error(elem.AccountTag())
		t.Fatal(test_acntTag)
	} else if elem.TokenTag() != test_tokTag {
		t.Error(elem.TokenTag())
		t.Fatal(test_tokTag)
	} else if elem.ToTa() != test_toTa {
		t.Error(elem.ToTa())
		t.Fatal(test_toTa)
	}
}

func TestElementJson(t *testing.T) {
	exp := time.Now().Add(24 * time.Hour)
	elem := New(test_id, exp, test_acntTag, test_tokTag, test_toTa)

	data, err := json.Marshal(elem)
	if err != nil {
		t.Fatal(err)
	}

	var elem2 Element
	if err := json.Unmarshal(data, &elem2); err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(&elem2, elem) {
		t.Error(&elem2)
		t.Fatal(elem)
	}
}
