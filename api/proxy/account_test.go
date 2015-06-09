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

package proxy

import (
	"testing"
)

func TestMainAccount(t *testing.T) {
	acnt := newMainAccount(test_acntTag, test_tokTag)
	if acnt.tag() != test_acntTag {
		t.Error(acnt.tag())
		t.Fatal(test_acntTag)
	} else if acnt.tokenTag() != test_tokTag {
		t.Error(acnt.tokenTag())
		t.Fatal(test_tokTag)
	} else if acnt.idProvider() != "" {
		t.Fatal(acnt.idProvider())
	} else if acnt.id() != "" {
		t.Fatal(acnt.id())
	}
}

func TestSubAccount(t *testing.T) {
	acnt := newSubAccount(test_acntTag, test_idpId, test_acntId)
	if acnt.tag() != test_acntTag {
		t.Error(acnt.tag())
		t.Fatal(test_acntTag)
	} else if acnt.tokenTag() != "" {
		t.Fatal(acnt.tokenTag())
	} else if acnt.idProvider() != test_idpId {
		t.Error(acnt.idProvider())
		t.Fatal(test_idpId)
	} else if acnt.id() != test_acntId {
		t.Error(acnt.id())
		t.Fatal(test_acntId)
	}
}
