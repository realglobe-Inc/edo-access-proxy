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
	"encoding/json"
	"github.com/realglobe-Inc/edo-lib/jwt"
	"github.com/realglobe-Inc/go-lib/erro"
	"net/http"
)

type request struct {
	toUri_   string
	toTa_    string
	acnt     *account
	relAcnts []*account
}

func parseProxyRequest(r *http.Request) (*request, error) {
	toUri := r.Header.Get(tagX_access_proxy_to)
	if toUri == "" {
		return nil, erro.New("no destination URI")
	}

	jt, err := jwt.Parse([]byte(r.Header.Get(tagX_access_proxy_users)))
	if err != nil {
		return nil, erro.Wrap(err)
	}
	data := jt.RawBody()
	var buffs map[string]*struct {
		TokTag string `json:"at_tag"`
		Iss    string `json:"iss"`
		Sub    string `json:"sub"`
	}
	if err := json.Unmarshal(data, &buffs); err != nil {
		return nil, erro.Wrap(err)
	}
	var acnt *account
	var relAcnts []*account
	for tag, buff := range buffs {
		if buff.TokTag != "" {
			if acnt != nil {
				return nil, erro.New("two main accounts")
			}
			acnt = newMainAccount(tag, buff.TokTag)
		} else {
			if relAcnts == nil {
				relAcnts = []*account{}
			} else if buff.Iss == "" {
				return nil, erro.New("no ID provider ID")
			} else if buff.Sub == "" {
				return nil, erro.New("no account ID")
			}
			relAcnts = append(relAcnts, newSubAccount(tag, buff.Iss, buff.Sub))
		}
	}
	r.Header.Del(tagX_access_proxy_to)
	r.Header.Del(tagX_access_proxy_users)
	return &request{
		toUri_:   toUri,
		toTa_:    r.Header.Get(tagX_access_proxy_to_id),
		acnt:     acnt,
		relAcnts: relAcnts,
	}, nil
}

// 転送先 URI を返す。
func (this *request) toUri() string {
	return this.toUri_
}

// 転送先 TA の ID を返す。
func (this *request) toTa() string {
	return this.toTa_
}

// 処理の主体の情報を返す。
func (this *request) account() *account {
	return this.acnt
}

// 処理の主体でないアカウントの情報を返す。
func (this *request) relatedAccounts() []*account {
	return this.relAcnts
}
