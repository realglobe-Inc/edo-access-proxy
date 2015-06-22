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
	"github.com/realglobe-Inc/edo-access-proxy/database/session"
	"github.com/realglobe-Inc/edo-lib/jwt"
	"github.com/realglobe-Inc/go-lib/erro"
	"net/http"
)

type request struct {
	toUri_  string
	toTa_   string
	acntTag string
	acnts   map[string]*session.Account
}

func parseRequest(r *http.Request) (*request, error) {
	toUri := r.Header.Get(tagX_access_proxy_to)
	if toUri == "" {
		return nil, erro.New("no destination URI")
	}

	jt, err := jwt.Parse([]byte(r.Header.Get(tagX_access_proxy_users)))
	if err != nil {
		return nil, erro.Wrap(err)
	}
	var acnts map[string]*session.Account
	if err := json.Unmarshal(jt.RawBody(), &acnts); err != nil {
		return nil, erro.Wrap(err)
	}
	var mainTag string
	for tag, acnt := range acnts {
		if acnt.TokenTag() != "" {
			if mainTag != "" {
				return nil, erro.New("two main accounts")
			}
			mainTag = tag
		}
	}
	if mainTag == "" {
		return nil, erro.New("no main account")
	}
	r.Header.Del(tagX_access_proxy_to)
	r.Header.Del(tagX_access_proxy_users)
	return &request{
		toUri_:  toUri,
		toTa_:   r.Header.Get(tagX_access_proxy_to_id),
		acntTag: mainTag,
		acnts:   acnts,
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

// 処理の主体のアカウントタグを返す。
func (this *request) accountTag() string {
	return this.acntTag
}

// アカウントの情報を返す。
func (this *request) accounts() map[string]*session.Account {
	return this.acnts
}
