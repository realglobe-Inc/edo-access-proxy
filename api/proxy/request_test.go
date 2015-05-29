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
	"fmt"
	"github.com/realglobe-Inc/edo-lib/base64url"
	"net/http"
	"reflect"
	"testing"
)

func TestRequest(t *testing.T) {
	r, err := http.NewRequest("GET", "http://localhost:1605", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Access-Proxy-To", test_ta+test_path)
	r.Header.Set("X-Access-Proxy-To-Id", test_ta)
	r.Header.Set("X-Access-Proxy-Users",
		base64url.EncodeToString([]byte(`{"alg":"none"}`))+"."+
			base64url.EncodeToString([]byte(`{"`+test_acntTag+`":{"at_tag":"`+test_tokTag+`"},"`+test_acntTag2+`":{"iss":"`+test_idp+`","sub":"`+test_acntId2+`"}}`))+".")

	req, err := parseRequest(r)
	if err != nil {
		t.Fatal(err)
	} else if req.toUri() != test_ta+test_path {
		t.Error(req.toUri())
		t.Fatal(test_ta + test_path)
	} else if req.toTa() != test_ta {
		t.Error(req.toTa())
		t.Fatal(test_ta)
	} else if acnt := newMainAccount(test_acntTag, test_tokTag); !reflect.DeepEqual(req.account(), acnt) {
		t.Error(req.account())
		t.Fatal(acnt)
	} else if acnts := []*account{newSubAccount(test_acntTag2, test_idp, test_acntId2)}; !reflect.DeepEqual(req.accounts(), acnts) {
		t.Error(fmt.Sprintf("%#v", req.accounts()))
		t.Fatal(fmt.Sprintf("%#v", acnts))
	}
}
