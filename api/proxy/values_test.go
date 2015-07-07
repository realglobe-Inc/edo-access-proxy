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
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	hashutil "github.com/realglobe-Inc/edo-id-provider/hash"
	idpdb "github.com/realglobe-Inc/edo-idp-selector/database/idp"
	"github.com/realglobe-Inc/edo-lib/jwk"
	"github.com/realglobe-Inc/edo-lib/jwt"
	"github.com/realglobe-Inc/edo-lib/jwt/audience"
	"github.com/realglobe-Inc/edo-lib/strset/strsetutil"
	"github.com/realglobe-Inc/go-lib/erro"
)

const (
	test_pref = "edo-access-proxy.api.proxy"

	test_frTaSigAlg = "ES384"
	test_hAlg       = "SHA256"
	test_tokTag     = "cAKWYXuohZ"
	test_tok        = "ZkTPOdBdh_bS2PqWnb1r8A3DqeKGCC"
	test_sessId     = "Xewtmrlnu5HVDzem5rmyGzoe2edQjI"

	test_idpId     = "https://idp.example.org"
	test_idpSigAlg = "ES256"
	test_cod       = "1SblzkyNc6O867zqdZYPM0T-a7g1n5"
	test_jti       = "R-seIeMPBly4xPAh"

	test_subIdpSigAlg = "ES256"
	test_subCod       = "iIxcrSU4j4ulTBIy4bOVjX9Epe5k5a"

	test_toTaId = "https://to.example.org"
	test_path   = "/api/gattai"

	test_acntId  = "IVcdq_bSuF6kiU6kid8-QDHMxVFkOR"
	test_acntTag = "inviter"

	test_subAcnt1Id  = "PJtJt6QCjxy2D0o-kg19BhE5bUC4tW"
	test_subAcnt1Tag = "invitee"

	test_subAcnt2Tag = "sub-user2"
	test_subAcnt2Id  = "lgmxuHfXfSTB-1js"
)

var (
	test_idpKey, _ = jwk.FromMap(map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "lpHYO1qpjU95B2sThPR2-1jv44axgaEDkQtcKNE-oZs",
		"y":   "soy5O11SFFFeYdhQVodXlYPIpeo0pCS69IxiVPPf0Tk",
		"d":   "3BhkCluOkm8d8gvaPD5FDG2zeEw2JKf3D5LwN-mYmsw",
	})
	test_subIdpKey, _ = jwk.FromMap(map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "vQ3EYqVi30Zd4NF0hbKdHIMZAngSrhwa3mxx74zXkDc",
		"y":   "OwPvhvTL0SlgB7SpucwBOyjbbY0V8M1-dS6FwkMPGD8",
		"d":   "Y4YXo4D_B5FMj_5oXizubBDWRWETRpWr8jX969odblA",
	})
	test_frTaKey, _ = jwk.FromMap(map[string]interface{}{
		"kty": "EC",
		"crv": "P-384",
		"x":   "HlrMhzZww_AkmHV-2gDR5n7t75673UClnC7V2GewWva_sg-4GSUguFalVgwnK0tQ",
		"y":   "fxS48Fy50SZFZ-RAQRWUZXZgRSWwiKVkqPTd6gypfpQNkXSwE69BXYIAQcfaLcf2",
		"d":   "Gp-7eC0G7PjGzKoiAmTQ1iLsLU3AEy3h-bKFWSZOanXqSWI6wqJVPEUsatNYBJoG",
	})
	test_scop = strsetutil.New("openid", "email")
)

// 関係する ID プロバイダが 1 つのリクエスト。
func newTestSingleRequest(idpId, toTaId string, body []byte) (*http.Request, error) {
	meth := "GET"
	var buff io.Reader
	if body != nil {
		meth = "POST"
		buff = bytes.NewReader(body)
	}
	r, err := http.NewRequest(meth, "http://localhost/", buff)
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

// セッションを使えるリクエスト。
func newTestSessionRequest(idpId, toTaId string, body []byte) (*http.Request, error) {
	meth := "GET"
	var buff io.Reader
	if body != nil {
		meth = "POST"
		buff = bytes.NewReader(body)
	}
	r, err := http.NewRequest(meth, "http://localhost/", buff)
	if err != nil {
		return nil, erro.Wrap(err)
	}
	acnts := jwt.New()
	acnts.SetHeader("alg", "none")
	acnts.SetClaim(test_acntTag, map[string]interface{}{"at_tag": test_tokTag})
	acntsBuff, err := acnts.Encode()
	if err != nil {
		return nil, erro.Wrap(err)
	}
	r.Header.Set("X-Access-Proxy-Users", string(acntsBuff))
	r.Header.Set("X-Access-Proxy-To", toTaId+test_path)

	return r, nil
}

// 関係する唯一の ID プロバイダからのレスポンス。
func newTestSingleIdpResponse(hndl *handler, idp idpdb.Element, toTaId string) (status int, header http.Header, body []byte, err error) {
	codTok := jwt.New()
	codTok.SetHeader("alg", test_idpSigAlg)
	codTok.SetClaim("iss", idp.Id())
	codTok.SetClaim("sub", test_cod)
	codTok.SetClaim("aud", toTaId)
	codTok.SetClaim("from_client", hndl.selfId)
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

// セッションが使える状況での ID プロバイダからのレスポンス。
func newTestIdpResponse(hndl *handler, idp idpdb.Element, toTaId string) (status int, header http.Header, body []byte, err error) {
	codTok := jwt.New()
	codTok.SetHeader("alg", test_idpSigAlg)
	codTok.SetClaim("iss", idp.Id())
	codTok.SetClaim("sub", test_cod)
	codTok.SetClaim("aud", toTaId)
	codTok.SetClaim("from_client", hndl.selfId)
	codTok.SetClaim("user_tag", test_acntTag)
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

func calcTestSubAccount2HashValue(idp string) string {
	return hashutil.Hashing(hashutil.Generator(test_hAlg).New(), []byte(idp), []byte{0}, []byte(test_subAcnt2Id))
}

// 関係する ID プロバイダが 2 つ以上のリクエスト。
func newTestMultiRequest(idpId, subIdpId, toTaId string, body []byte) (*http.Request, error) {
	meth := "GET"
	var buff io.Reader
	if body != nil {
		meth = "POST"
		buff = bytes.NewReader(body)
	}
	r, err := http.NewRequest(meth, "http://localhost/", buff)
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
	acnts.SetClaim(test_subAcnt2Tag, map[string]interface{}{
		"iss": subIdpId,
		"sub": test_subAcnt2Id,
	})
	acntsBuff, err := acnts.Encode()
	if err != nil {
		return nil, erro.Wrap(err)
	}
	r.Header.Set("X-Access-Proxy-Users", string(acntsBuff))
	r.Header.Set("X-Access-Proxy-To", toTaId+test_path)

	return r, nil
}

// 1 つ目の ID プロバイダからのレスポンス。
func newTestMainIdpResponse(hndl *handler, idp idpdb.Element, subIdpId, toTaId, subAcnt2HVal string) (status int, header http.Header, body, codTokData, refData []byte, err error) {
	ref := jwt.New()
	ref.SetHeader("alg", test_idpSigAlg)
	ref.SetClaim("iss", idp.Id())
	ref.SetClaim("sub", hndl.selfId)
	ref.SetClaim("aud", audience.New(subIdpId))
	ref.SetClaim("exp", time.Now().Add(time.Minute))
	ref.SetClaim("jti", test_jti)
	ref.SetClaim("to_client", toTaId)
	ref.SetClaim("related_users", map[string]string{
		test_subAcnt2Tag: subAcnt2HVal,
	})
	ref.SetClaim("hash_alg", test_hAlg)
	if err := ref.Sign(idp.Keys()); err != nil {
		return 0, nil, nil, nil, nil, erro.Wrap(err)
	}
	refData, err = ref.Encode()
	if err != nil {
		return 0, nil, nil, nil, nil, erro.Wrap(err)
	}
	refHash := hashutil.Hashing(hashutil.Generator(test_hAlg).New(), refData)

	codTok := jwt.New()
	codTok.SetHeader("alg", test_idpSigAlg)
	codTok.SetClaim("iss", idp.Id())
	codTok.SetClaim("sub", test_cod)
	codTok.SetClaim("aud", toTaId)
	codTok.SetClaim("from_client", hndl.selfId)
	codTok.SetClaim("user_tag", test_acntTag)
	codTok.SetClaim("user_tags", []string{test_subAcnt1Tag})
	codTok.SetClaim("ref_hash", refHash)
	if err := codTok.Sign(idp.Keys()); err != nil {
		return 0, nil, nil, nil, nil, erro.Wrap(err)
	}
	codTokData, err = codTok.Encode()
	if err != nil {
		return 0, nil, nil, nil, nil, erro.Wrap(err)
	}

	body, err = json.Marshal(map[string]interface{}{
		"code_token": string(codTokData),
		"referral":   string(refData),
	})
	if err != nil {
		return 0, nil, nil, nil, nil, erro.Wrap(err)
	}

	return http.StatusOK, http.Header{"Content-Type": {"application/json"}}, body, codTokData, refData, nil
}

// 1 つ目以降の ID プロバイダからのレスポンス。
func newTestSubIdpResponse(hndl *handler, idp idpdb.Element, toTaId string, ref []byte) (status int, header http.Header, body, codTokData []byte, err error) {
	refHash := hashutil.Hashing(hashutil.Generator(test_hAlg).New(), ref)

	codTok := jwt.New()
	codTok.SetHeader("alg", test_subIdpSigAlg)
	codTok.SetClaim("iss", idp.Id())
	codTok.SetClaim("sub", test_subCod)
	codTok.SetClaim("aud", toTaId)
	codTok.SetClaim("from_client", hndl.selfId)
	codTok.SetClaim("user_tags", []string{test_subAcnt2Tag})
	codTok.SetClaim("ref_hash", refHash)
	if err := codTok.Sign(idp.Keys()); err != nil {
		return 0, nil, nil, nil, erro.Wrap(err)
	}
	codTokData, err = codTok.Encode()
	if err != nil {
		return 0, nil, nil, nil, erro.Wrap(err)
	}

	body, err = json.Marshal(map[string]interface{}{
		"code_token": string(codTokData),
	})
	if err != nil {
		return 0, nil, nil, nil, erro.Wrap(err)
	}

	return http.StatusOK, http.Header{"Content-Type": {"application/json"}}, body, codTokData, nil
}
