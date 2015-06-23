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
	"github.com/realglobe-Inc/go-lib/erro"
)

// アカウント情報。
type Account struct {
	tokTag string

	idp string
	id  string
}

// 処理の主体のアカウント情報をつくる。
func NewMainAccount(tokTag string) *Account {
	return &Account{
		tokTag: tokTag,
	}
}

// 処理の主体でないアカウントのアカウント情報をつくる。
func NewSubAccount(idp, acntId string) *Account {
	return &Account{
		idp: idp,
		id:  acntId,
	}
}

// アクセストークンタグを返す。
func (this *Account) TokenTag() string {
	return this.tokTag
}

// 属す ID プロバイダを返す。
func (this *Account) IdProvider() string {
	return this.idp
}

// アカウント ID を返す。
func (this *Account) Id() string {
	return this.id
}

//  {
//      "at_tag": <アクセストークンタグ>
//  }
//
// または、
//
//  {
//      "iss": <属す ID プロバイダの ID>,
//      "sub": <アカウント ID>,
//  }
func (this *Account) MarshalJSON() (data []byte, err error) {
	m := map[string]interface{}{}
	if this.tokTag != "" {
		m["at_tag"] = this.tokTag
	} else {
		m["iss"] = this.idp
		m["sub"] = this.id
	}
	return json.Marshal(m)
}

func (this *Account) UnmarshalJSON(data []byte) error {
	var buff struct {
		TokTag string `json:"at_tag"`
		Idp    string `json:"iss"`
		Id     string `json:"sub"`
	}
	if err := json.Unmarshal(data, &buff); err != nil {
		return erro.Wrap(err)
	}

	if buff.TokTag != "" {
		this.tokTag = buff.TokTag
	} else if buff.Idp == "" {
		return erro.New("no ID provider ID")
	} else if buff.Id == "" {
		return erro.New("no account ID")
	} else {
		this.idp = buff.Idp
		this.id = buff.Id
	}
	return nil
}
