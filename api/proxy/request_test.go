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
	"net/http"
	"reflect"
	"testing"

	"github.com/realglobe-Inc/edo-access-proxy/database/session"
	"github.com/realglobe-Inc/edo-lib/base64url"
)

func TestRequest(t *testing.T) {
	r, err := http.NewRequest("GET", "http://localhost:1605", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Access-Proxy-To", test_toTaId+test_path)
	r.Header.Set("X-Access-Proxy-To-Id", test_toTaId)
	r.Header.Set("X-Access-Proxy-Users",
		base64url.EncodeToString([]byte(`{"alg":"none"}`))+"."+
			base64url.EncodeToString([]byte(`{"`+test_acntTag+`":{"at_tag":"`+test_tokTag+`"},"`+
				test_subAcnt1Tag+`":{"iss":"`+test_idpId+`","sub":"`+test_subAcnt1Id+`"}}`))+".")

	req, err := parseRequest(r)
	if err != nil {
		t.Fatal(err)
	} else if req.toUri() != test_toTaId+test_path {
		t.Error(req.toUri())
		t.Fatal(test_toTaId + test_path)
	} else if req.toTa() != test_toTaId {
		t.Error(req.toTa())
		t.Fatal(test_toTaId)
	} else if req.accountTag() != test_acntTag {
		t.Error(req.accountTag())
		t.Fatal(test_acntTag)
	} else if acnts := map[string]*session.Account{
		test_acntTag:     session.NewMainAccount(test_tokTag),
		test_subAcnt1Tag: session.NewSubAccount(test_idpId, test_subAcnt1Id),
	}; !reflect.DeepEqual(req.accounts(), acnts) {
		t.Error(fmt.Sprintf("%#v", req.accounts()))
		t.Fatal(fmt.Sprintf("%#v", acnts))
	}
}
