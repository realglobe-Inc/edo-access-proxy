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

// TA 間連携代行エンドポイント。
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/realglobe-Inc/edo-access-proxy/database/session"
	"github.com/realglobe-Inc/edo-auth/database/token"
	keydb "github.com/realglobe-Inc/edo-id-provider/database/key"
	hashutil "github.com/realglobe-Inc/edo-id-provider/hash"
	idpdb "github.com/realglobe-Inc/edo-idp-selector/database/idp"
	idperr "github.com/realglobe-Inc/edo-idp-selector/error"
	requtil "github.com/realglobe-Inc/edo-idp-selector/request"
	"github.com/realglobe-Inc/edo-lib/jwk"
	"github.com/realglobe-Inc/edo-lib/jwt"
	logutil "github.com/realglobe-Inc/edo-lib/log"
	"github.com/realglobe-Inc/edo-lib/rand"
	"github.com/realglobe-Inc/edo-lib/server"
	"github.com/realglobe-Inc/go-lib/erro"
	"github.com/realglobe-Inc/go-lib/rglog/level"
	"net/http"
	"net/url"
	"time"
)

type handler struct {
	stopper *server.Stopper

	selfId  string
	sigAlg  string
	sigKid  string
	hashAlg string

	sessLabel   string
	sessDbExpIn time.Duration
	jtiLen      int
	jtiExpIn    time.Duration
	fileThres   int

	keyDb  keydb.Db
	idpDb  idpdb.Db
	tokDb  token.Db
	sessDb session.Db
	idGen  rand.Generator

	tr http.RoundTripper

	debug bool
}

func New(
	stopper *server.Stopper,
	selfId string,
	sigAlg string,
	sigKid string,
	hashAlg string,
	sessLabel string,
	sessDbExpIn time.Duration,
	jtiLen int,
	jtiExpIn time.Duration,
	fileThres int,
	keyDb keydb.Db,
	idpDb idpdb.Db,
	tokDb token.Db,
	sessDb session.Db,
	idGen rand.Generator,
	tr http.RoundTripper,
	debug bool,
) http.Handler {
	return &handler{
		stopper,
		selfId,
		sigAlg,
		sigKid,
		hashAlg,
		sessLabel,
		sessDbExpIn,
		jtiLen,
		jtiExpIn,
		fileThres,
		keyDb,
		idpDb,
		tokDb,
		sessDb,
		idGen,
		tr,
		debug,
	}
}

func (this *handler) httpClient() *http.Client {
	return &http.Client{Transport: this.tr}
}

func (this *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var sender *requtil.Request

	// panic 対策。
	defer func() {
		if rcv := recover(); rcv != nil {
			w.Header().Set(tagX_access_proxy_error, fmt.Sprint(rcv))
			idperr.RespondJson(w, r, erro.New(rcv), sender)
			return
		}
	}()

	if this.stopper != nil {
		this.stopper.Stop()
		defer this.stopper.Unstop()
	}

	//////////////////////////////
	server.LogRequest(level.DEBUG, r, this.debug)
	//////////////////////////////

	sender = requtil.Parse(r, "")
	log.Info(sender, ": Received proxy request")
	defer log.Info(sender, ": Handled proxy request")

	if err := (&environment{this, sender}).serve(w, r); err != nil {
		w.Header().Set(tagX_access_proxy_error, erro.Unwrap(err).Error())
		idperr.RespondJson(w, r, erro.Wrap(err), sender)
		return
	}
}

// environment のメソッドは idperr.Error を返す。
type environment struct {
	*handler

	sender *requtil.Request
}

func (this *environment) serve(w http.ResponseWriter, r *http.Request) error {
	req, err := parseRequest(r)
	if err != nil {
		return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusBadRequest, err))
	}

	log.Debug(this.sender, ": Parsed proxy request")

	uri, err := url.Parse(req.toUri())
	if err != nil {
		return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusBadRequest, err))
	}

	log.Debug(this.sender, ": Destination is "+req.toUri())

	toTa := req.toTa()
	if toTa == "" {
		toTa = uri.Scheme + "://" + uri.Host
	}

	log.Debug(this.sender, ": To-TA is "+toTa)

	r.URL = uri
	r.Host = uri.Host

	sess, err := this.sessDb.GetByParams(toTa, req.accounts())
	if err != nil {
		return erro.Wrap(err)
	} else if sess != nil && !time.Now().After(sess.Expires()) {
		return this.proxyWithSession(w, r, sess, req.accountTag())
	}
	return this.proxyThroughIdProvider(w, r, toTa, req.accountTag(), req.accounts())
}

// セッションを利用して TA 間連携する。
func (this *environment) proxyWithSession(w http.ResponseWriter, r *http.Request, sess *session.Element, acntTag string) (err error) {
	var buff *buffer
	if r.Body != nil {
		buff = newBuffer(r.Body, this.fileThres, tempPrefix)
		defer buff.dispose()
		r.Body = buff
	}

	r.AddCookie(&http.Cookie{
		Name:  tagEdo_cooperation,
		Value: sess.Id(),
	})

	log.Debug(this.sender, ": Proxy with session "+logutil.Mosaic(sess.Id()))

	r.RequestURI = ""
	server.LogRequest(level.DEBUG, r, this.debug)
	resp, err := this.httpClient().Do(r)
	if err != nil {
		if isDestinationError(err) {
			return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusNotFound, err))
		} else {
			return erro.Wrap(err)
		}
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, this.debug)

	if coopErr := resp.Header.Get(tagX_edo_cooperation_error); coopErr == "" {
		return copyResponse(w, resp)
	} else {
		log.Warn(this.sender, ": Cooperation error: "+coopErr)
	}

	if buff != nil {
		if err := buff.lastRollback(); err != nil {
			return erro.Wrap(err)
		}
		r.Body = buff
	}
	r.Header.Del(tagCookie)
	return this.proxyThroughIdProvider(w, r, sess.ToTa(), acntTag, sess.Accounts())
}

// ID プロバイダを介して TA 間連携する。
func (this *environment) proxyThroughIdProvider(w http.ResponseWriter, r *http.Request, toTa string, acntTag string, acnts map[string]*session.Account) error {
	tok, err := this.tokDb.GetByTag(acnts[acntTag].TokenTag())
	if err != nil {
		return erro.Wrap(err)
	} else if tok == nil {
		return erro.Wrap(idperr.New(idperr.Invalid_request, "no access token "+acnts[acntTag].TokenTag(), http.StatusBadRequest, err))
	} else if time.Now().After(tok.Expires()) {
		return erro.Wrap(idperr.New(idperr.Invalid_request, "access token "+acnts[acntTag].TokenTag()+" expired", http.StatusBadRequest, err))
	}

	log.Debug(this.sender, ": Access token "+logutil.Mosaic(tok.Tag())+" is exist")

	idps, tagToAcnt, idpToTagToAcnt, err := this.getIdpAndAccountMaps(this.idpDb, tok.IdProvider(), acnts)
	if err != nil {
		return erro.Wrap(err)
	}

	log.Debug(this.sender, ": ID provider checks are passed")

	keys, err := this.keyDb.Get()
	if err != nil {
		return erro.Wrap(err)
	}

	codTok, ref, err := this.getMainCoopCode(idps[tok.IdProvider()], keys, toTa, tok, acntTag, tagToAcnt, idpToTagToAcnt)
	if err != nil {
		return erro.Wrap(err)
	}

	log.Debug(this.sender, ": Got main cooperation code from "+tok.IdProvider())

	codToks := []string{codTok}
	for idpId, subTagToAcnt := range idpToTagToAcnt {
		codTok, err := this.getSubCoopCode(idps[idpId], keys, ref, subTagToAcnt)
		if err != nil {
			return erro.Wrap(err)
		}

		log.Debug(this.sender, ": Got sub cooperation code from "+idpId)

		codToks = append(codToks, codTok)
	}

	for _, codTok := range codToks {
		r.Header.Add(tagX_edo_code_tokens, codTok)
	}

	log.Debug(this.sender, ": Proxy through ID provider")

	r.RequestURI = ""
	server.LogRequest(level.DEBUG, r, this.debug)
	resp, err := this.httpClient().Do(r)
	if err != nil {
		if isDestinationError(err) {
			return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusNotFound, err))
		} else {
			return erro.Wrap(err)
		}
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, this.debug)

	for _, cook := range resp.Cookies() {
		if cook.Name != this.sessLabel {
			continue
		}
		now := time.Now()
		exp := cook.Expires
		if exp.IsZero() {
			exp = now.Add(time.Second * time.Duration(cook.MaxAge))
		}
		sess := session.New(cook.Value, exp, toTa, acnts)
		if err := this.sessDb.Save(sess, now.Add(this.sessDbExpIn)); err != nil {
			log.Warn(erro.Unwrap(err))
			log.Debug(erro.Wrap(err))
		} else {
			log.Debug(this.sender, ": Saved session "+logutil.Mosaic(sess.Id()))
		}
	}

	return copyResponse(w, resp)
}

// 各種マップを作成する。
// idps: ID プロバイダの ID から ID プロバイダ情報へのマップ。
// tagToAcnt: 主体の ID プロバイダに属すアカウントの、アカウントタグからアカウント情報へのマップ。
// idpToTagToAcnt: 主体の属さない ID プロバイダとそこに属すアカウントの、
// ID プロバイダの ID -> アカウントタグ -> アカウント情報のマップ。
func (this *environment) getIdpAndAccountMaps(idpDb idpdb.Db, mainIdpId string, acnts map[string]*session.Account) (idps map[string]idpdb.Element, tagToAcnt map[string]*session.Account, idpToTagToAcnt map[string]map[string]*session.Account, err error) {
	idps = map[string]idpdb.Element{}
	{
		idp, err := idpDb.Get(mainIdpId)
		if err != nil {
			return nil, nil, nil, erro.Wrap(err)
		} else if idp == nil {
			return nil, nil, nil, erro.New(idperr.New(idperr.Invalid_request, "main ID provider "+mainIdpId+" is not exist", http.StatusBadRequest, nil))
		}
		idps[idp.Id()] = idp
	}

	tagToAcnt = map[string]*session.Account{}
	for acntTag, acnt := range acnts {
		if acnt.TokenTag() != "" {
			continue
		} else if acnt.IdProvider() == mainIdpId {
			tagToAcnt[acntTag] = acnt
			continue
		}

		if idps[acnt.IdProvider()] == nil {
			idp, err := idpDb.Get(acnt.IdProvider())
			if err != nil {
				return nil, nil, nil, erro.Wrap(err)
			} else if idp == nil {
				return nil, nil, nil, erro.New(idperr.New(idperr.Invalid_request, "sub ID provider "+acnt.IdProvider()+" is not exist", http.StatusBadRequest, nil))
			}
			idps[idp.Id()] = idp
		}

		if idpToTagToAcnt == nil {
			idpToTagToAcnt = map[string]map[string]*session.Account{}
		}
		subTagToAcnt := idpToTagToAcnt[acnt.IdProvider()]
		if subTagToAcnt == nil {
			subTagToAcnt = map[string]*session.Account{}
			idpToTagToAcnt[acnt.IdProvider()] = subTagToAcnt
		}
		subTagToAcnt[acntTag] = acnt
	}

	return idps, tagToAcnt, idpToTagToAcnt, nil
}

// 主体の属す ID プロバイダから仲介コードを取得する。
func (this *environment) getMainCoopCode(idp idpdb.Element, keys []jwk.Key, toTa string,
	tok *token.Element, acntTag string, tagToAcnt map[string]*session.Account, idpToTagToAcnt map[string]map[string]*session.Account) (codTok, ref string, err error) {

	params := map[string]interface{}{}

	// response_type
	reqRef := false
	respType := tagCode_token
	if len(idpToTagToAcnt) > 0 {
		reqRef = true
		respType += " " + tagReferral
	}
	params[tagResponse_type] = respType

	// to_client
	params[tagTo_client] = toTa

	// from_client
	params[tagFrom_client] = this.selfId

	// grant_type
	params[tagGrant_type] = tagAccess_token

	// access_token
	params[tagAccess_token] = tok.Id()

	// scope
	// expires_in

	// user_tag
	params[tagUser_tag] = acntTag

	// users
	if len(tagToAcnt) > 0 {
		tagToAcntId := map[string]string{}
		for tag, acnt := range tagToAcnt {
			tagToAcntId[tag] = acnt.Id()
		}
		params[tagUsers] = tagToAcntId
	}

	// hash_alg
	hGen := hashutil.Generator(this.hashAlg)
	if !hGen.Available() {
		return "", "", erro.New("unsupported hash algorithm " + this.hashAlg)
	}
	params[tagHash_alg] = this.hashAlg

	// related_users
	// related_issuers
	if reqRef {
		hFun := hGen.New()
		idps := []string{}
		tagToAcntHash := map[string]string{}
		for idpId, tagToAcnt := range idpToTagToAcnt {
			for tag, subAcnt := range tagToAcnt {
				hFun.Reset()
				tagToAcntHash[tag] = hashutil.Hashing(hFun, []byte(idpId), []byte{0}, []byte(subAcnt.Id()))
			}
			idps = append(idps, idpId)
		}
		params[tagRelated_users] = tagToAcntHash
		params[tagRelated_issuers] = idps
	}

	// client_assertion_type
	params[tagClient_assertion_type] = cliAssTypeJwt_bearer

	// client_assertion
	ass, err := makeAssertion(this.handler, keys, idp.CoopFromUri())
	if err != nil {
		return "", "", erro.Wrap(err)
	}
	params[tagClient_assertion] = string(ass)

	data, err := json.Marshal(params)
	if err != nil {
		return "", "", erro.Wrap(err)
	}

	r, err := http.NewRequest("POST", idp.CoopFromUri(), bytes.NewReader(data))
	if err != nil {
		return "", "", erro.Wrap(err)
	}
	r.Header.Set(tagContent_type, contTypeJson)
	log.Debug(this.sender, ": Made main cooperation-from request")

	server.LogRequest(level.DEBUG, r, this.debug)
	resp, err := this.httpClient().Do(r)
	if err != nil {
		return "", "", erro.Wrap(err)
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, this.debug)

	if resp.StatusCode != http.StatusOK {
		return "", "", erro.New("invalid state ", resp.StatusCode)
	} else if contType := resp.Header.Get(tagContent_type); contType != contTypeJson {
		return "", "", erro.New("invalid content type " + contType)
	}

	var buff struct {
		CodTok string `json:"code_token"`
		Ref    string `json:"referral"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&buff); err != nil {
		return "", "", erro.Wrap(err)
	} else if buff.CodTok == "" {
		return "", "", erro.New("cannot get code token")
	} else if reqRef && buff.Ref == "" {
		return "", "", erro.New("cannot get referral")
	}

	return buff.CodTok, buff.Ref, nil
}

// 主体の属さない ID プロバイダから仲介コードを取得する。
func (this *environment) getSubCoopCode(idp idpdb.Element, keys []jwk.Key, ref string,
	tagToAcnt map[string]*session.Account) (codTok string, err error) {

	// response_type
	// grant_type
	params := map[string]interface{}{
		tagResponse_type: tagCode_token,
		tagGrant_type:    tagReferral,
	}

	// referral
	params[tagReferral] = ref

	// users
	if len(tagToAcnt) > 0 {
		tagToAcntId := map[string]string{}
		for tag, acnt := range tagToAcnt {
			tagToAcntId[tag] = acnt.Id()
		}
		params[tagUsers] = tagToAcntId
	}

	// client_assertion_type
	params[tagClient_assertion_type] = cliAssTypeJwt_bearer

	// client_assertion
	ass, err := makeAssertion(this.handler, keys, idp.CoopFromUri())
	if err != nil {
		return "", erro.Wrap(err)
	}
	params[tagClient_assertion] = string(ass)

	data, err := json.Marshal(params)
	if err != nil {
		return "", erro.Wrap(err)
	}

	r, err := http.NewRequest("POST", idp.CoopFromUri(), bytes.NewReader(data))
	if err != nil {
		return "", erro.Wrap(err)
	}
	r.Header.Set(tagContent_type, contTypeJson)
	log.Debug(this.sender, ": Made sub cooperation-from request")

	server.LogRequest(level.DEBUG, r, this.debug)
	resp, err := this.httpClient().Do(r)
	if err != nil {
		return "", erro.Wrap(err)
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, this.debug)

	if resp.StatusCode != http.StatusOK {
		return "", erro.New("invalid state ", resp.StatusCode)
	} else if contType := resp.Header.Get(tagContent_type); contType != contTypeJson {
		return "", erro.New("invalid content type " + contType)
	}

	var buff struct {
		CodTok string `json:"code_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&buff); err != nil {
		return "", erro.Wrap(err)
	} else if buff.CodTok == "" {
		return "", erro.New("cannot get code token")
	}

	return buff.CodTok, nil
}

// TA 認証用署名をつくる。
func makeAssertion(hndl *handler, keys []jwk.Key, aud string) ([]byte, error) {
	ass := jwt.New()
	ass.SetHeader(tagAlg, hndl.sigAlg)
	if hndl.sigKid != "" {
		ass.SetHeader(tagKid, hndl.sigKid)
	}
	ass.SetClaim(tagIss, hndl.selfId)
	ass.SetClaim(tagSub, hndl.selfId)
	ass.SetClaim(tagAud, aud)
	ass.SetClaim(tagJti, hndl.idGen.String(hndl.jtiLen))
	now := time.Now()
	ass.SetClaim(tagExp, now.Add(hndl.jtiExpIn).Unix())
	ass.SetClaim(tagIat, now.Unix())
	if err := ass.Sign(keys); err != nil {
		return nil, erro.Wrap(err)
	}
	data, err := ass.Encode()
	if err != nil {
		return nil, erro.Wrap(err)
	}

	return data, nil
}
