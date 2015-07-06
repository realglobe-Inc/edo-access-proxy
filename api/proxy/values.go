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

const (
	// アンダースコア。
	tagAccess_token          = "access_token"
	tagAlg                   = "alg"
	tagAud                   = "aud"
	tagClient_assertion      = "client_assertion"
	tagClient_assertion_type = "client_assertion_type"
	tagCode_token            = "code_token"
	tagExp                   = "exp"
	tagFrom_client           = "from_client"
	tagGrant_type            = "grant_type"
	tagHash_alg              = "hash_alg"
	tagIat                   = "iat"
	tagIss                   = "iss"
	tagJti                   = "jti"
	tagKid                   = "kid"
	tagReferral              = "referral"
	tagRelated_issuers       = "related_issuers"
	tagRelated_users         = "related_users"
	tagResponse_type         = "response_type"
	tagSub                   = "sub"
	tagTo_client             = "to_client"
	tagUser_tag              = "user_tag"
	tagUsers                 = "users"

	// 頭大文字、ハイフン。
	tagContent_type            = "Content-Type"
	tagCookie                  = "Cookie"
	tagEdo_cooperation         = "Edo-Cooperation"
	tagX_access_proxy_error    = "X-Access-Proxy-Error"
	tagX_access_proxy_to       = "X-Access-Proxy-To"
	tagX_access_proxy_to_id    = "X-Access-Proxy-To-Id"
	tagX_access_proxy_users    = "X-Access-Proxy-Users"
	tagX_edo_code_tokens       = "X-Edo-Code-Tokens"
	tagX_edo_cooperation_error = "X-Edo-Cooperation-Error"
)

const (
	cliAssTypeJwt_bearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	contTypeJson = "application/json"

	tmpPref = "edo-access-proxy"
)
