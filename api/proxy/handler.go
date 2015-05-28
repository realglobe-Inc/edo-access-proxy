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
	"github.com/realglobe-Inc/edo-access-proxy/database/session"
	"github.com/realglobe-Inc/edo-auth/database/token"
	keydb "github.com/realglobe-Inc/edo-id-provider/database/key"
	idpdb "github.com/realglobe-Inc/edo-idp-selector/database/idp"
	idperr "github.com/realglobe-Inc/edo-idp-selector/error"
	requtil "github.com/realglobe-Inc/edo-idp-selector/request"
	"github.com/realglobe-Inc/edo-lib/base64url"
	edohash "github.com/realglobe-Inc/edo-lib/hash"
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

	jtiLen    int
	jtiExpIn  time.Duration
	fileThres int

	keyDb  keydb.Db
	idpDb  idpdb.Db
	tokDb  token.Db
	sessDb session.Db

	idGen rand.Generator
	tr    *http.Transport
}

func New(
	stopper *server.Stopper,
	selfId string,
	sigAlg string,
	sigKid string,
	hashAlg string,
	jtiLen int,
	jtiExpIn time.Duration,
	fileThres int,
	keyDb keydb.Db,
	idpDb idpdb.Db,
	tokDb token.Db,
	sessDb session.Db,
	idGen rand.Generator,
	tr *http.Transport,
) http.Handler {
	return &handler{
		stopper:   stopper,
		selfId:    selfId,
		sigAlg:    sigAlg,
		sigKid:    sigKid,
		hashAlg:   hashAlg,
		jtiLen:    jtiLen,
		jtiExpIn:  jtiExpIn,
		fileThres: fileThres,
		keyDb:     keyDb,
		idpDb:     idpDb,
		tokDb:     tokDb,
		sessDb:    sessDb,
		idGen:     idGen,
		tr:        tr,
	}
}

func (this *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var sender *requtil.Request

	// panic 対策。
	defer func() {
		if rcv := recover(); rcv != nil {
			idperr.RespondApiError(w, r, erro.New(rcv), sender)
			return
		}
	}()

	if this.stopper != nil {
		this.stopper.Stop()
		defer this.stopper.Unstop()
	}

	//////////////////////////////
	server.LogRequest(level.DEBUG, r, true)
	//////////////////////////////

	sender = requtil.Parse(r, "")
	log.Info(sender, ": Received proxy request")
	defer log.Info(sender, ": Handled proxy request")

	if err := this.serve(w, r, sender); err != nil {
		idperr.RespondApiError(w, r, erro.Wrap(err), sender)
		return
	}
}

func (this *handler) serve(w http.ResponseWriter, r *http.Request, sender *requtil.Request) error {
	req, err := parseRequest(r)
	if err != nil {
		return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusBadRequest, err))
	}

	log.Debug(sender, ": Parsed proxy request")

	uri, err := url.Parse(req.toUri())
	if err != nil {
		return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusBadRequest, err))
	}

	log.Debug(sender, ": Destination is "+req.toUri())

	toTa := req.toTa()
	if toTa == "" {
		toTa = uri.Scheme + "://" + uri.Host
	}

	log.Debug(sender, ": To-TA is "+toTa)

	r.URL = uri
	r.Host = uri.Host

	if len(req.relatedAccounts()) == 0 {
		sess, err := this.sessDb.GetByParams(req.account().tag(), req.account().tokenTag(), toTa)
		if err != nil {
			return erro.Wrap(err)
		} else if sess != nil && !time.Now().After(sess.Expires()) {
			return this.proxyWithSession(w, r, sess, sender)
		}
	}
	return this.proxyThroughIdProvider(w, r, req.account(), req.relatedAccounts(), toTa, sender)
}

// セッションを利用して TA 間連携する。
func (this *handler) proxyWithSession(w http.ResponseWriter, r *http.Request, sess *session.Element, sender *requtil.Request) (err error) {
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

	log.Debug(sender, ": Proxy with session "+logutil.Mosaic(sess.Id()))

	r.RequestURI = ""
	server.LogRequest(level.DEBUG, r, true)
	resp, err := this.httpClient().Do(r)
	if err != nil {
		if isDestinationError(err) {
			return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusNotFound, err))
		} else {
			return erro.Wrap(err)
		}
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, true)

	if coopErr := resp.Header.Get(tagX_edo_cooperation_error); coopErr == "" {
		return copyResponse(w, resp)
	} else {
		log.Warn(sender, ": Cooperation error: "+coopErr)
	}

	if buff != nil {
		if err := buff.lastRollback(); err != nil {
			return erro.Wrap(err)
		}
		r.Body = buff
	}
	r.Header.Del(tagCookie)
	return this.proxyThroughIdProvider(w, r, newMainAccount(sess.AccountTag(), sess.TokenTag()), nil, sess.ToTa(), sender)
}

// ID プロバイダを介して TA 間連携する。
func (this *handler) proxyThroughIdProvider(w http.ResponseWriter, r *http.Request, acnt *account, relAcnts []*account, toTa string, sender *requtil.Request) error {
	tok, err := this.tokDb.GetByTag(acnt.tokenTag())
	if err != nil {
		return erro.Wrap(err)
	} else if tok == nil {
		return erro.Wrap(idperr.New(idperr.Invalid_request, "no access token "+acnt.tokenTag(), http.StatusBadRequest, err))
	} else if time.Now().After(tok.Expires()) {
		return erro.Wrap(idperr.New(idperr.Invalid_request, "access token "+acnt.tokenTag()+" expired", http.StatusBadRequest, err))
	}

	log.Debug(sender, ": Access token "+logutil.Mosaic(tok.Tag())+" is exist")

	idps := map[string]idpdb.Element{}
	idp, err := this.idpDb.Get(tok.IdProvider())
	if err != nil {
		return erro.Wrap(err)
	} else if idp == nil {
		return erro.New("ID provider " + tok.IdProvider() + " is not exist")
	}
	idps[idp.Id()] = idp
	log.Debug(sender, ": ID provider "+idp.Id()+" is exist")

	tagToAcnt := map[string]*account{}
	idpToTagToRelAcnt := map[string]map[string]*account{}
	for _, relAcnt := range relAcnts {
		if idps[relAcnt.idProvider()] == nil {
			idp, err := this.idpDb.Get(relAcnt.idProvider())
			if err != nil {
				return erro.Wrap(err)
			}
			idps[idp.Id()] = idp
			log.Debug(sender, ": ID provider "+idp.Id()+" is exist")
		}

		if relAcnt.idProvider() == tok.IdProvider() {
			tagToAcnt[relAcnt.tag()] = relAcnt
		} else {
			tagToRelAcnt := idpToTagToRelAcnt[relAcnt.idProvider()]
			if tagToRelAcnt == nil {
				tagToRelAcnt = map[string]*account{}
				idpToTagToRelAcnt[relAcnt.idProvider()] = tagToRelAcnt
			}
		}
	}

	keys, err := this.keyDb.Get()
	if err != nil {
		return erro.Wrap(err)
	}

	codTok, ref, err := this.getMainCoopCode(idps[tok.IdProvider()], keys, toTa, tok, acnt, tagToAcnt, idpToTagToRelAcnt, sender)
	if err != nil {
		return erro.Wrap(err)
	}

	log.Debug(sender, ": Got main cooperation code from "+tok.IdProvider())

	codToks := []string{codTok}
	for idpId, tagToRelAcnt := range idpToTagToRelAcnt {
		codTok, err := this.getSubCoopCode(idps[idpId], keys, ref, tagToRelAcnt, sender)
		if err != nil {
			return erro.Wrap(err)
		}

		log.Debug(sender, ": Got sub cooperation code from "+idpId)

		codToks = append(codToks, codTok)
	}

	for _, codTok := range codToks {
		r.Header.Add(tagX_edo_code_tokens, codTok)
	}

	log.Debug(sender, ": Proxy through ID provider")

	r.RequestURI = ""
	server.LogRequest(level.DEBUG, r, true)
	resp, err := this.httpClient().Do(r)
	if err != nil {
		if isDestinationError(err) {
			return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusNotFound, err))
		} else {
			return erro.Wrap(err)
		}
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, true)

	return copyResponse(w, resp)
}

func (this *handler) getMainCoopCode(idp idpdb.Element, keys []jwk.Key, toTa string,
	tok *token.Element, acnt *account, tagToAcnt map[string]*account, idpToTagToRelAcnt map[string]map[string]*account,
	sender *requtil.Request) (codTok, ref string, err error) {

	params := map[string]interface{}{}

	// response_type
	reqRef := false
	respType := tagCode_token
	if len(idpToTagToRelAcnt) > 0 {
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
	params[tagUser_tag] = acnt.tag()

	// users
	if len(tagToAcnt) > 0 {
		tagToAcntId := map[string]string{}
		for tag, acnt := range tagToAcnt {
			tagToAcntId[tag] = acnt.id()
		}
		params[tagUsers] = tagToAcntId
	}

	// hash_alg
	hash, err := edohash.HashFunction(this.hashAlg)
	if err != nil {
		return "", "", erro.Wrap(err)
	}
	params[tagHash_alg] = this.hashAlg

	// related_users
	// related_issuers
	if reqRef {
		h := hash.New()
		idps := []string{}
		tagToRelAcntHash := map[string]string{}
		for idpId, tagToRelAcnt := range idpToTagToRelAcnt {
			for tag, relAcnt := range tagToRelAcnt {
				h.Reset()
				h.Write([]byte(idpId))
				h.Write([]byte{0})
				h.Write([]byte(relAcnt.id()))
				sum := h.Sum(nil)
				tagToRelAcntHash[tag] = base64url.EncodeToString(sum[:len(sum)/2])
			}
			idps = append(idps, idpId)
		}
		params[tagRelated_users] = tagToRelAcntHash
		params[tagRelated_issuers] = idps
	}

	// client_assertion_type
	params[tagClient_assertion_type] = cliAssTypeJwt_bearer

	// client_assertion
	jt := jwt.New()
	jt.SetHeader(tagAlg, this.sigAlg)
	if this.sigKid != "" {
		jt.SetHeader(tagKid, this.sigKid)
	}
	jt.SetClaim(tagIss, this.selfId)
	jt.SetClaim(tagSub, this.selfId)
	jt.SetClaim(tagAud, idp.CoopFromUri())
	jt.SetClaim(tagJti, this.idGen.String(this.jtiLen))
	now := time.Now()
	jt.SetClaim(tagExp, now.Add(this.jtiExpIn).Unix())
	jt.SetClaim(tagIat, now.Unix())
	if err := jt.Sign(keys); err != nil {
		return "", "", erro.Wrap(err)
	}
	assData, err := jt.Encode()
	if err != nil {
		return "", "", erro.Wrap(err)
	}
	params[tagClient_assertion] = string(assData)

	data, err := json.Marshal(params)
	if err != nil {
		return "", "", erro.Wrap(err)
	}

	r, err := http.NewRequest("POST", idp.CoopFromUri(), bytes.NewReader(data))
	r.Header.Set(tagContent_type, contTypeJson)
	log.Debug(sender, ": Made main cooperation-from request")

	server.LogRequest(level.DEBUG, r, true)
	resp, err := this.httpClient().Do(r)
	if err != nil {
		return "", "", erro.Wrap(err)
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, true)

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

func (this *handler) getSubCoopCode(idp idpdb.Element, keys []jwk.Key, toTa string,
	tagToRelAcnt map[string]*account, sender *requtil.Request) (codTok string, err error) {
	panic("not yet implemented")
}

func (this *handler) httpClient() *http.Client {
	return &http.Client{Transport: this.tr}
}
