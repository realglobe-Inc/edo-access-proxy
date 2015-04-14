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

package token

import (
	"time"
)

// アクセストークン。
type Element interface {
	Id() string

	// バックエンド通知用タグ。
	Tag() string

	// 有効期限。
	ExpiresIn() time.Time

	// 発行元 ID プロバイダの ID。
	IdProvider() string

	// 許可されているスコープ。
	Scopes() map[string]bool
}
