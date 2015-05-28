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

import ()

// リクエストに含まれるアカウント情報。
type account struct {
	tag_ string

	tokTag string

	idp string
	id_ string
}

// 処理の主体たるアカウント情報をつくる
func newMainAccount(tag, tokTag string) *account {
	return &account{
		tag_:   tag,
		tokTag: tokTag,
	}
}

// 処理の主体でないアカウント情報をつくる
func newSubAccount(tag, idp, id string) *account {
	return &account{
		tag_: tag,
		idp:  idp,
		id_:  id,
	}
}

// アカウントタグを返す。
func (this *account) tag() string {
	return this.tag_
}

// アクセストークンタグを返す。
func (this *account) tokenTag() string {
	return this.tokTag
}

// 属す ID プロバイダを返す。
func (this *account) idProvider() string {
	return this.idp
}

// アカウント ID を返す。
func (this *account) id() string {
	return this.id_
}
