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

// TA 認証代行エンドポイント。
package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/realglobe-Inc/edo-access-proxy/database/session"
	keydb "github.com/realglobe-Inc/edo-id-provider/database/key"
	idperr "github.com/realglobe-Inc/edo-idp-selector/error"
	"github.com/realglobe-Inc/edo-lib/hash"
	"github.com/realglobe-Inc/edo-lib/jwk"
	logutil "github.com/realglobe-Inc/edo-lib/log"
	"github.com/realglobe-Inc/edo-lib/reader"
	"github.com/realglobe-Inc/edo-lib/server"
	"github.com/realglobe-Inc/go-lib/erro"
	"github.com/realglobe-Inc/go-lib/rglog/level"
)

type handler struct {
	stopper *server.Stopper

	selfId  string
	hashAlg string

	sessLabel   string
	sessDbExpIn time.Duration
	fileThres   int
	fileMax     int
	filePref    string

	keyDb  keydb.Db
	sessDb session.Db
	conn   *http.Client

	debug bool
}

func New(
	stopper *server.Stopper,
	selfId string,
	hashAlg string,
	sessLabel string,
	sessDbExpIn time.Duration,
	fileThres int,
	fileMax int,
	filePref string,
	keyDb keydb.Db,
	sessDb session.Db,
	conn *http.Client,
	debug bool,
) http.Handler {
	return &handler{
		stopper,
		selfId,
		hashAlg,
		sessLabel,
		sessDbExpIn,
		fileThres,
		fileMax,
		filePref,
		keyDb,
		sessDb,
		conn,
		debug,
	}
}

func (hndl *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var logPref string

	// panic 対策。
	defer func() {
		if rcv := recover(); rcv != nil {
			w.Header().Set(tagX_edo_access_proxy_error, fmt.Sprint(rcv))
			idperr.RespondJson(w, r, erro.New(rcv), logPref)
			return
		}
	}()

	if hndl.stopper != nil {
		hndl.stopper.Stop()
		defer hndl.stopper.Unstop()
	}

	logPref = server.ParseSender(r) + ": "

	server.LogRequest(level.DEBUG, r, hndl.debug, logPref)

	log.Info(logPref, "Received proxy request")
	defer log.Info(logPref, "Handled proxy request")

	if err := (&environment{hndl, logPref}).serve(w, r); err != nil {
		w.Header().Set(tagX_edo_access_proxy_error, idperr.From(err).ErrorDescription())
		idperr.RespondJson(w, r, erro.Wrap(err), logPref)
		return
	}
}

// environment のメソッドは idperr.Error を返す。
type environment struct {
	*handler

	logPref string
}

func (env *environment) serve(w http.ResponseWriter, r *http.Request) error {
	req, err := parseRequest(r)
	if err != nil {
		return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusBadRequest, err))
	}

	log.Debug(env.logPref, "Parsed proxy request to ", req.toUri())

	r.URL = req.toUri()
	r.Host = req.toUri().Host
	return env.tryForward(w, r, req)
}

// 転送してみる。
// セッションが必要なのに確立できてないせいで失敗したら、セッションを確立させながらもう一回転送する。
func (env *environment) tryForward(w http.ResponseWriter, r *http.Request, req *request) error {
	sess, err := env.sessDb.GetByToTa(r.Host)
	if err != nil {
		return erro.Wrap(err)
	} else if sess != nil {
		// セッションがある。
		log.Debug(env.logPref, "Session "+logutil.Mosaic(sess.Id())+" is exist")
		r.AddCookie(&http.Cookie{Name: env.sessLabel, Value: sess.Id()})
	} else {
		// セッションが無い。
		log.Debug(env.logPref, "Session is not exist")
	}

	var buff *reader.Resettable
	if r.Body != nil {
		buff = reader.NewResettable(r.Body, env.fileThres, env.filePref, env.fileMax)
		defer buff.Dispose()
		r.Body = buff
	}

	r.RequestURI = ""
	server.LogRequest(level.DEBUG, r, env.debug, env.logPref)
	resp, err := env.conn.Do(r)
	if err != nil {
		if isDestinationError(err) {
			return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusNotFound, err))
		} else {
			return erro.Wrap(err)
		}
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, env.debug, env.logPref)

	if resp.Header.Get(tagX_edo_auth_ta_error) == "" {
		// セッション確立済み、または、セッション不要だった。
		log.Debug(env.logPref, "Forwarding succeeded")
		return server.CopyResponse(w, resp)
	}

	if sess != nil {
		if err := env.sessDb.Delete(sess); err != nil {
			log.Warn(env.logPref, erro.Unwrap(err))
			log.Debug(env.logPref, erro.Wrap(err))
		}
	}

	sessResp, err := parseResponse(resp, env.sessLabel)
	if err != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			return erro.Wrap(idperr.New(idperr.Access_denied, erro.Unwrap(err).Error(), http.StatusForbidden, err))
		}
		log.Warn(env.logPref, erro.Unwrap(err))
		log.Debug(env.logPref, erro.Wrap(err))
		return server.CopyResponse(w, resp)
	}

	log.Debug(env.logPref, "Forwarding failed because of no valid session")

	if err := buff.LastReset(); err != nil {
		return erro.Wrap(err)
	}
	return env.forward(w, r, req, sessResp)
}

// セッションを確立しつつ転送する。
func (env *environment) forward(w http.ResponseWriter, r *http.Request, req *request, sessResp *response) error {

	keys, err := env.keyDb.Get()
	if err != nil {
		return erro.Wrap(idperr.New(idperr.Access_denied, erro.Unwrap(err).Error(), http.StatusForbidden, err))
	}

	// 鍵を読み込めた。
	log.Debug(env.logPref, "Keys are exist")

	hashAlg := r.Header.Get(tagX_edo_auth_hash_function)
	if hashAlg == "" {
		hashAlg = env.hashAlg
	}

	tokSig, err := sign(keys, hashAlg, sessResp.token())
	if err != nil {
		return erro.Wrap(err)
	}

	// 署名できた。
	log.Debug(env.logPref, "Signed")

	r.AddCookie(&http.Cookie{Name: env.sessLabel, Value: sessResp.sessionId()})
	r.Header.Set(tagX_edo_auth_ta_id, env.selfId)
	r.Header.Set(tagX_edo_auth_ta_token_sign, tokSig)
	r.Header.Set(tagX_edo_auth_hash_function, hashAlg)
	r.RequestURI = ""

	server.LogRequest(level.DEBUG, r, env.debug, env.logPref)
	resp, err := env.conn.Do(r)
	if err != nil {
		if isDestinationError(err) {
			return erro.Wrap(idperr.New(idperr.Invalid_request, erro.Unwrap(err).Error(), http.StatusNotFound, err))
		} else {
			return erro.Wrap(err)
		}
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, env.debug, env.logPref)

	// 認証された。
	log.Debug(env.logPref, "Authentication finished")

	if resp.Header.Get(tagX_edo_auth_ta_error) == "" {
		// セッションを保存。
		if err := env.sessDb.Save(session.New(sessResp.sessionId(), sessResp.sessionExpires(), req.toUri().Host), time.Now().Add(env.sessDbExpIn)); err != nil {
			log.Err(env.logPref, erro.Unwrap(err))
			log.Debug(env.logPref, erro.Wrap(err))
		} else {
			log.Debug(env.logPref, "Session was saved")
		}
	}

	return server.CopyResponse(w, resp)
}

// プロキシ先がおかしいかどうか。
func isDestinationError(err error) bool {
	for {
		switch e := erro.Unwrap(err).(type) {
		case *net.OpError:
			return true
		case *url.Error:
			if e.Err != nil {
				err = e.Err
			} else {
				return false
			}
		case *erro.Tracer:
			err = e.Cause()
		default:
			return false
		}
	}
}

// プロキシ先からのお題に署名する。
func sign(keys []jwk.Key, hashAlg, tok string) (string, error) {
	var priKey *rsa.PrivateKey
	for _, key := range keys {
		if key.Type() == "RSA" && key.Private() != nil {
			priKey = key.Private().(*rsa.PrivateKey)
			break
		}
	}
	if priKey == nil {
		return "", erro.New("no key")
	}

	hGen := hash.Generator(hashAlg)
	if hGen == 0 {
		return "", erro.New("unsupported hash algorithm " + hashAlg)
	}

	hFun := hGen.New()
	hFun.Write([]byte(tok))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priKey, hGen, hFun.Sum(nil))
	if err != nil {
		return "", erro.Wrap(err)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}
