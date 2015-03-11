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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"github.com/realglobe-Inc/edo-lib/crypto"
	"github.com/realglobe-Inc/edo-lib/server"
	"github.com/realglobe-Inc/go-lib/erro"
	"github.com/realglobe-Inc/go-lib/rglog/level"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	headerAccProxUri = "X-Edo-Access-Proxy-Uri"
	headerAccProxErr = "X-Edo-Access-Proxy-Error"

	headerTaId = "X-Edo-Ta-Id"

	headerAuthTaErr      = "X-Edo-Auth-Ta-Error"
	headerAuthTaId       = "X-Edo-Auth-Ta-Id"
	headerAuthTaToken    = "X-Edo-Auth-Ta-Token"
	headerAuthTaTokenSig = "X-Edo-Auth-Ta-Token-Sign"
	headerAuthHashFunc   = "X-Edo-Auth-Hash-Function"

	cookTaSess = "X-Edo-Auth-Ta-Session"
)

// Web プロキシ。
func proxyApi(sys *system, w http.ResponseWriter, r *http.Request) error {

	if rawUri := r.Header.Get(headerAccProxUri); rawUri != "" {
		// ヘッダによる指定。
		if u, err := url.Parse(rawUri); err != nil {
			// URL 指定がおかしい。
			return erro.Wrap(server.NewStatusError(http.StatusBadRequest, "invalid uri "+rawUri, erro.Wrap(err)))
		} else {
			r.Header.Del(headerAccProxUri)
			r.URL = u
			r.Host = u.Host
		}
	} else if !strings.HasPrefix(r.RequestURI, "http://") && !strings.HasPrefix(r.RequestURI, "https://") {
		// URL 指定がプロキシ形式になってない。
		return erro.Wrap(server.NewStatusError(http.StatusBadRequest, "no scheme in request uri", nil))
	}

	buff, err := readHead(r.Body, sys.threSize)
	if err != nil && err != io.EOF {
		return erro.Wrap(err)
	}

	// err は nil か io.EOF。

	if err != nil {
		// 全部読み込めた。
		log.Debug("body was completely read")

		return tryForward(sys, w, r, buff)
	} else {
		// 全部は読めなかった。
		log.Debug("body is larger than buffer size")

		return checkAndForward(sys, w, r, buff)
	}
}

// 転送してみる。
// セッションが必要なのに確立できてないせいで失敗したら、セッションを確立させながらもう一回転送する。
func tryForward(sys *system, w http.ResponseWriter, r *http.Request, body []byte) error {
	taId := r.Header.Get(headerTaId)
	if taId == "" {
		taId = sys.taId
	} else {
		defer r.Header.Del(headerTaId)
	}

	sess, _, err := sys.session(r.Host, taId, nil)
	if err != nil {
		return erro.Wrap(err)
	} else if sess != nil {
		// セッションがある。
		log.Debug("authenticated session is exist")
		r.AddCookie(&http.Cookie{Name: cookTaSess, Value: sess.id})
	} else {
		// セッションが無い。
		log.Debug("session is not exist")
	}
	cli, err := sys.client(r.Host)
	if err != nil {
		return erro.Wrap(err)
	}

	r.RequestURI = ""
	r.Body = ioutil.NopCloser(bytes.NewReader(body))

	server.LogRequest(level.DEBUG, r, true)
	resp, err := cli.Do(r)
	if err != nil {
		err = erro.Wrap(err)
		if isDestinationError(err) {
			return erro.Wrap(server.NewStatusError(http.StatusNotFound, "cannot connect "+uriBase(r.URL), err))
		} else {
			return err
		}
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, true)

	if resp.Header.Get(headerAuthTaErr) != "" {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			// セッションが必要なのに確立できていなかった。
			log.Debug("first forwarding failed because of no valid session")

			if sess != nil {
				log.Debug("remove old invalid session")

				// 古いセッションを削除。
				if err := sys.removeSession(sess); err != nil {
					return erro.Wrap(err)
				}
			}

			return startSession(sys, w, r, body, resp)
		case http.StatusForbidden:
			// 許可されなかった。
			if sess != nil {
				log.Debug("remove old invalid session")

				// 古いセッションを削除。
				if err := sys.removeSession(sess); err != nil {
					return erro.Wrap(err)
				}
			}

			return copyResponse(resp, w)
		default:
			// セッション云々以前のエラー。
			log.Debug("first forwarding failed")

			return copyResponse(resp, w)
		}
	}

	// セッション確立済み、または、セッション不要だった。
	log.Debug("first forwarding succeeded")

	return copyResponse(resp, w)
}

// セッションを検査、または、確立してから転送する。
func checkAndForward(sys *system, w http.ResponseWriter, r *http.Request, bodyHead []byte) error {
	taId := r.Header.Get(headerTaId)
	if taId == "" {
		taId = sys.taId
	} else {
		defer r.Header.Del(headerTaId)
	}

	req, err := http.NewRequest("HEAD", r.URL.String(), nil)
	if err != nil {
		return erro.Wrap(err)
	}

	sess, _, err := sys.session(r.Host, taId, nil)
	if err != nil {
		return erro.Wrap(err)
	} else if sess != nil {
		// セッションがある。
		log.Debug("authenticated session is exist")
		req.AddCookie(&http.Cookie{Name: cookTaSess, Value: sess.id})
	} else {
		// セッションが無い。
		log.Debug("session is not exist")
	}
	cli, err := sys.client(r.Host)
	if err != nil {
		return erro.Wrap(err)
	}

	server.LogRequest(level.DEBUG, req, true)
	ckResp, err := cli.Do(req)
	if err != nil {
		err = erro.Wrap(err)
		if isDestinationError(err) {
			return erro.Wrap(server.NewStatusError(http.StatusNotFound, "cannot connect "+uriBase(r.URL), err))
		} else {
			return err
		}
	}
	defer ckResp.Body.Close()
	server.LogResponse(level.DEBUG, ckResp, true)

	if ckResp.Header.Get(headerAuthTaErr) != "" {
		switch ckResp.StatusCode {
		case http.StatusUnauthorized:
			// セッションが必要なのに確立できていなかった。
			log.Debug("first forwarding failed because of no valid session")

			if sess != nil {
				log.Debug("remove old invalid session")

				// 古いセッションを削除。
				if err := sys.removeSession(sess); err != nil {
					return erro.Wrap(err)
				}
			}

			return startSession(sys, w, r, bodyHead, ckResp)
		case http.StatusForbidden:
			// 許可されなかった。
			if sess != nil {
				log.Debug("remove old invalid session")

				// 古いセッションを削除。
				if err := sys.removeSession(sess); err != nil {
					return erro.Wrap(err)
				}
			}

			return copyResponse(ckResp, w)
		default:
			// セッション云々以前のエラー。
			log.Debug("check failed")

			return copyResponse(ckResp, w)
		}
	}

	// セッション確立済み、または、セッション不要だった。
	log.Debug("check succeeded")

	if sess != nil {
		// セッションがある。
		log.Debug("authenticated session is exist")
		r.AddCookie(&http.Cookie{Name: cookTaSess, Value: sess.id})
	} else {
		// セッションが無い。
		log.Debug("session is not exist")
	}
	r.RequestURI = ""
	r.Body = ioutil.NopCloser(io.MultiReader(bytes.NewReader(bodyHead), r.Body))

	server.LogRequest(level.DEBUG, r, true)
	resp, err := cli.Do(r)
	if err != nil {
		err = erro.Wrap(err)
		if isDestinationError(err) {
			return erro.Wrap(server.NewStatusError(http.StatusNotFound, "cannot connect "+uriBase(r.URL), err))
		} else {
			return err
		}
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, true)

	return copyResponse(resp, w)
}

// セッション開始レスポンスを受けてセッション開始しつつ転送する。
func startSession(sys *system, w http.ResponseWriter, r *http.Request, bodyHead []byte, ckResp *http.Response) error {
	taId := r.Header.Get(headerTaId)
	if taId == "" {
		taId = sys.taId
	} else {
		defer r.Header.Del(headerTaId)
	}

	sess, sessToken := parseSession(ckResp)
	if sess == nil {
		return erro.Wrap(server.NewStatusError(http.StatusForbidden, "no cookie "+cookTaSess, nil))
	} else if sessToken == "" {
		return erro.Wrap(server.NewStatusError(http.StatusForbidden, "no header field "+headerAuthTaToken, nil))
	}
	cli, err := sys.client(r.Host)
	if err != nil {
		return erro.Wrap(err)
	}

	expiDate := getExpirationDate(sess, sys.sessMargin)

	// 認証用データが揃ってた。
	log.Debug("authentication data was found")

	priKey, _, err := sys.privateKey(taId, nil)
	if err != nil {
		return erro.Wrap(err)
	} else if priKey == nil {
		return erro.Wrap(server.NewStatusError(http.StatusForbidden, "no private key of "+taId, nil))
	}

	// 秘密鍵を用意できた。
	log.Debug("private key of " + taId + " is exist")

	hashName := r.Header.Get(headerAuthHashFunc)
	if hashName == "" {
		hashName = sys.hashName
	}

	tokenSign, err := sign(priKey, hashName, sessToken)
	if err != nil {
		return erro.Wrap(err)
	}

	// 署名できた。
	log.Debug("signed")

	r.AddCookie(&http.Cookie{Name: cookTaSess, Value: sess.Value})
	r.Header.Set(headerAuthTaId, taId)
	r.Header.Set(headerAuthTaTokenSig, tokenSign)
	r.Header.Set(headerAuthHashFunc, hashName)
	r.RequestURI = ""
	r.Body = ioutil.NopCloser(io.MultiReader(bytes.NewReader(bodyHead), r.Body))

	server.LogRequest(level.DEBUG, r, true)
	resp, err := cli.Do(r)
	if err != nil {
		err = erro.Wrap(err)
		if isDestinationError(err) {
			return erro.Wrap(server.NewStatusError(http.StatusNotFound, "cannot connect "+uriBase(r.URL), err))
		} else {
			return err
		}
	}
	defer resp.Body.Close()
	server.LogResponse(level.DEBUG, resp, true)

	// 認証された。
	log.Debug("authentication finished")

	if resp.Header.Get(headerAuthTaErr) == "" {
		// セッションを保存。
		if _, err := sys.addSession(&session{id: sess.Value, host: r.Host, taId: taId}, expiDate); err != nil {
			err = erro.Wrap(err)
			log.Err(erro.Unwrap(err))
			log.Debug(err)
		} else {
			log.Debug("session was saved")
		}
	}

	return copyResponse(resp, w)
}

// クエリパラメータ等を除いた URL を得る。
func uriBase(url *url.URL) string {
	return url.Scheme + "://" + url.Host + url.Path
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
		case *server.StatusError:
			if e.Cause() != nil {
				err = e.Cause()
			} else {
				return false
			}
		default:
			return false
		}
	}
}

// プロキシ先の認証開始レスポンスから必要情報を抜き出す。
func parseSession(resp *http.Response) (sess *http.Cookie, sessToken string) {
	for _, cook := range resp.Cookies() {
		if cook.Name == cookTaSess {
			sess = cook
			break
		}
	}

	return sess, resp.Header.Get(headerAuthTaToken)
}

// プロキシ先からのレスポンスをリクエスト元へのレスポンスに写す。
func copyResponse(resp *http.Response, w http.ResponseWriter) error {
	// ヘッダフィールドのコピー。
	for key, vals := range resp.Header {
		for _, val := range vals {
			w.Header().Add(key, val)
		}
	}

	// ステータスのコピー。
	w.WriteHeader(resp.StatusCode)

	// ボディのコピー。
	if _, err := io.Copy(w, resp.Body); err != nil {
		return erro.Wrap(err)
	}

	return nil
}

// プロキシ先からのお題に署名する。
func sign(priKey *rsa.PrivateKey, hashName, token string) (string, error) {
	hash, err := crypto.ParseHashFunction(hashName)
	if err != nil {
		return "", erro.Wrap(err)
	}

	h := hash.New()
	h.Write([]byte(token))
	buff, err := rsa.SignPKCS1v15(rand.Reader, priKey, hash, h.Sum(nil))
	if err != nil {
		return "", erro.Wrap(err)
	}

	return base64.StdEncoding.EncodeToString(buff), nil
}

// プロキシ先が提示したセッションの有効期限を読み取る。
func getExpirationDate(sess *http.Cookie, margin time.Duration) (expiDate time.Time) {
	// プロキシ先で破棄されていると失敗してしまう実装なので、遊びを設けて返す。
	if float64(sess.MaxAge) > margin.Seconds() {
		return time.Now().Add(time.Duration(sess.MaxAge)*time.Second - margin)
	} else if !sess.Expires.IsZero() {
		return sess.Expires.Add(-margin)
	} else {
		return time.Time{}
	}
}

// io.Reader から最初の maxSize までを読む。
// 読み込めるサイズが maxSize 未満だった場合のみ EOF を返す。
func readHead(src io.Reader, maxSize int) (head []byte, err error) {
	buff := make([]byte, maxSize)
	switch n, err := io.ReadFull(src, buff); err {
	case nil:
		// バッファが埋まった。
		return buff, nil
	case io.EOF, io.ErrUnexpectedEOF:
		// 全部バッファに入った。
		return buff[:n], io.EOF
	default:
		// 読み込みエラー。
		return nil, erro.Wrap(err)
	}
}
