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

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	idpdb "github.com/realglobe-Inc/edo-idp-selector/database/idp"
	"github.com/realglobe-Inc/edo-lib/jwk"
	"github.com/realglobe-Inc/edo-lib/jwt"
	"github.com/realglobe-Inc/go-lib/erro"
)

const (
	test_logPath = "/tmp/edo-access-proxy.log"
	test_logSize = 100000000
	test_logNum  = 10
	test_logAddr = "127.0.0.1:24224"
	test_logTag  = "edo-access-proxy"
	test_socPort = 12345
	test_socPath = "/tmp/edo-access-proxy.sock"
	test_monAddr = "localhost"

	test_tokId  = "ZkTPOdBdh_bS2PqWnb1r8A3DqeKGCC"
	test_tokTag = "cAKWYXuohZ"

	test_idpSigAlg = "ES256"
	test_cod       = "1SblzkyNc6O867zqdZYPM0T-a7g1n5"

	test_path = "/api/gattai"

	test_acntTag     = "inviter"
	test_subAcnt1Id  = "PJtJt6QCjxy2D0o-kg19BhE5bUC4tW"
	test_subAcnt1Tag = "invitee"
)

var (
	test_idpKey, _ = jwk.FromMap(map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "lpHYO1qpjU95B2sThPR2-1jv44axgaEDkQtcKNE-oZs",
		"y":   "soy5O11SFFFeYdhQVodXlYPIpeo0pCS69IxiVPPf0Tk",
		"d":   "3BhkCluOkm8d8gvaPD5FDG2zeEw2JKf3D5LwN-mYmsw",
	})
	test_key, _ = jwk.FromMap(map[string]interface{}{
		"kty": "EC",
		"crv": "P-384",
		"x":   "HlrMhzZww_AkmHV-2gDR5n7t75673UClnC7V2GewWva_sg-4GSUguFalVgwnK0tQ",
		"y":   "fxS48Fy50SZFZ-RAQRWUZXZgRSWwiKVkqPTd6gypfpQNkXSwE69BXYIAQcfaLcf2",
		"d":   "Gp-7eC0G7PjGzKoiAmTQ1iLsLU3AEy3h-bKFWSZOanXqSWI6wqJVPEUsatNYBJoG",
	})
)

// 関係する ID プロバイダが 1 つのリクエスト。
func newTestRequest(selfUri, idpId, toTaId string, body []byte) (*http.Request, error) {
	meth := "GET"
	var buff io.Reader
	if body != nil {
		meth = "POST"
		buff = bytes.NewReader(body)
	}
	r, err := http.NewRequest(meth, selfUri, buff)
	if err != nil {
		return nil, erro.Wrap(err)
	}
	acnts := jwt.New()
	acnts.SetHeader("alg", "none")
	acnts.SetClaim(test_acntTag, map[string]interface{}{"at_tag": test_tokTag})
	acnts.SetClaim(test_subAcnt1Tag, map[string]interface{}{
		"iss": idpId,
		"sub": test_subAcnt1Id,
	})
	acntsBuff, err := acnts.Encode()
	if err != nil {
		return nil, erro.Wrap(err)
	}
	r.Header.Set("X-Access-Proxy-Users", string(acntsBuff))
	r.Header.Set("X-Access-Proxy-To", toTaId+test_path)

	return r, nil
}

// 関係する唯一の ID プロバイダからのレスポンス。
func newTestIdpResponse(param *parameters, idp idpdb.Element, toTaId string) (status int, header http.Header, body []byte, err error) {
	codTok := jwt.New()
	codTok.SetHeader("alg", test_idpSigAlg)
	codTok.SetClaim("iss", idp.Id())
	codTok.SetClaim("sub", test_cod)
	codTok.SetClaim("aud", toTaId)
	codTok.SetClaim("from_client", param.selfId)
	codTok.SetClaim("user_tag", test_acntTag)
	codTok.SetClaim("user_tags", []string{test_subAcnt1Tag})
	if err := codTok.Sign(idp.Keys()); err != nil {
		return 0, nil, nil, erro.Wrap(err)
	}
	data, err := codTok.Encode()
	if err != nil {
		return 0, nil, nil, erro.Wrap(err)
	}
	body, err = json.Marshal(map[string]interface{}{
		"code_token": string(data),
	})
	if err != nil {
		return 0, nil, nil, erro.Wrap(err)
	}

	return http.StatusOK, http.Header{"Content-Type": {"application/json"}}, body, nil
}

func newTestToTaResponse() (status int, header http.Header, body []byte, err error) {
	return http.StatusOK, http.Header{"Nanka-No-Header": {"abcde"}}, []byte("efghi"), nil
}
