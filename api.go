package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"github.com/realglobe-Inc/edo/util"
	"github.com/realglobe-Inc/go-lib-rg/erro"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	headerTaId       = "X-Edo-Ta-Id"
	headerTaToken    = "X-Edo-Ta-Token"
	headerTaTokenSig = "X-Edo-Ta-Token-Sign"
	headerHashFunc   = "X-Edo-Hash-Function"

	headerAccProxErr = "X-Edo-Access-Proxy-Error"

	headerTaAuthErr = "X-Edo-Ta-Auth-Error"

	cookieTaSess = "X-Edo-Ta-Session"
)


// Web プロキシ。
func proxyApi(sys *system, w http.ResponseWriter, r *http.Request) error {

	if !strings.HasPrefix(r.RequestURI, "http://") && !strings.HasPrefix(r.RequestURI, "https://") {
		return erro.Wrap(util.NewHttpStatusError(http.StatusBadRequest, "no scheme in request uri", nil))
	}

	taId := r.Header.Get(headerTaId)
	if taId == "" {
		taId = sys.taId
	}

	sess, _, err := sys.session(uriBase(r.URL), taId, nil)
	if err != nil {
		return erro.Wrap(err)
	}

	if sess != nil {
		// セッション確立済み。
		log.Debug("authenticated session is exist")
		return forward(sys, w, r, taId, sess)
	} else {
		// セッション未確立。
		log.Debug("session is not exist")
		return startSession(sys, w, r, taId)
	}
}

// 転送する。
func forward(sys *system, w http.ResponseWriter, r *http.Request, taId string, sess *session) error {
	r.AddCookie(&http.Cookie{Name: cookieTaSess, Value: sess.id})
	r.RequestURI = ""

	////////////////////////////////////////////////////////////
	util.LogRequest(r, true)
	////////////////////////////////////////////////////////////
	resp, err := sess.cli.Do(r)
	if err != nil {
		err = erro.Wrap(err)
		if isDestinationError(err) {
			return erro.Wrap(util.NewHttpStatusError(http.StatusNotFound, "cannot connect "+uriBase(r.URL), err))
		} else {
			return err
		}
	}
	defer resp.Body.Close()
	////////////////////////////////////////////////////////////
	util.LogResponse(resp, true)
	////////////////////////////////////////////////////////////

	log.Debug("forwarded")

	if resp.StatusCode == http.StatusUnauthorized && resp.Header.Get(headerTaAuthErr) != "" {
		// edo-auth で 401 Unauthorized なら、タイミングの問題なので startSession からやり直す。
		// 古いセッションは上書きされるので消す必要無し。
		return startSession(sys, w, r, taId)
	}

	return copyResponse(resp, w)
}

// セッション開始。
func startSession(sys *system, w http.ResponseWriter, r *http.Request, taId string) error {

	cli := &http.Client{}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return erro.Wrap(err)
	}

	r.RequestURI = ""
	r.Body = ioutil.NopCloser(bytes.NewReader(body))

	////////////////////////////////////////////////////////////
	util.LogRequest(r, true)
	////////////////////////////////////////////////////////////
	resp, err := cli.Do(r)
	if err != nil {
		err = erro.Wrap(err)
		if isDestinationError(err) {
			return erro.Wrap(util.NewHttpStatusError(http.StatusNotFound, "cannot connect "+uriBase(r.URL), err))
		} else {
			return err
		}
	}
	defer resp.Body.Close()
	////////////////////////////////////////////////////////////
	util.LogResponse(resp, true)
	////////////////////////////////////////////////////////////

	log.Debug("sent raw request")

	if resp.Header.Get(headerTaAuthErr) == "" || resp.StatusCode != http.StatusUnauthorized {
		// 相手側が TA 認証を必要としていなかったのかもしれない。
		return copyResponse(resp, w)
	}

	// 相手側 TA も認証始めた。
	log.Debug("authentication started")

	sess, sessToken := parseSession(resp)
	if sess == nil {
		return erro.Wrap(util.NewHttpStatusError(http.StatusForbidden, "no cookie "+cookieTaSess, nil))
	} else if sessToken == "" {
		return erro.Wrap(util.NewHttpStatusError(http.StatusForbidden, "no header field "+headerTaToken, nil))
	}

	expiDate := getExpirationDate(sess)

	// 認証用データが揃ってた。
	log.Debug("authentication data was found")

	priKey, _, err := sys.privateKey(taId, nil)
	if err != nil {
		return erro.Wrap(err)
	} else if priKey == nil {
		return erro.Wrap(util.NewHttpStatusError(http.StatusForbidden, "no private key of "+taId, nil))
	}

	// 秘密鍵を用意できた。
	log.Debug("private key of " + taId + " is exist")

	hashName := r.Header.Get(headerHashFunc)
	if hashName == "" {
		hashName = sys.hashName
	}

	tokenSign, err := sign(priKey, hashName, sessToken)
	if err != nil {
		return erro.Wrap(err)
	}

	// 署名できた。
	log.Debug("signed")

	r.AddCookie(&http.Cookie{Name: cookieTaSess, Value: sess.Value})
	r.Header.Set(headerTaId, taId)
	r.Header.Set(headerTaTokenSig, tokenSign)
	r.Header.Set(headerHashFunc, hashName)
	r.RequestURI = ""
	r.Body = ioutil.NopCloser(bytes.NewReader(body))

	////////////////////////////////////////////////////////////
	util.LogRequest(r, true)
	////////////////////////////////////////////////////////////
	resp, err = cli.Do(r)
	if err != nil {
		err = erro.Wrap(err)
		if isDestinationError(err) {
			return erro.Wrap(util.NewHttpStatusError(http.StatusNotFound, "cannot connect "+uriBase(r.URL), err))
		} else {
			return err
		}
	}
	defer resp.Body.Close()
	////////////////////////////////////////////////////////////
	util.LogResponse(resp, true)
	////////////////////////////////////////////////////////////

	// 認証された。
	log.Debug("authentication finished")

	if resp.Header.Get(headerTaAuthErr) == "" {
		// セッションを保存。
		if _, err := sys.addSession(&session{id: sess.Value, uri: uriBase(r.URL), taId: taId, cli: cli}, expiDate); err != nil {
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
		case *util.HttpStatusError:
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

// 相手側 TA の認証開始レスポンスから必要情報を抜き出す。
func parseSession(resp *http.Response) (sess *http.Cookie, sessToken string) {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieTaSess {
			sess = cookie
			break
		}
	}

	return sess, resp.Header.Get(headerTaToken)
}

// 相手側 TA からのレスポンスをリクエスト元へのレスポンスに写す。
func copyResponse(resp *http.Response, w http.ResponseWriter) error {
	// ヘッダフィールドのコピー。
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
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

// 相手側 TA からのお題に署名する。
func sign(priKey *rsa.PrivateKey, hashName, token string) (string, error) {
	hash, err := util.ParseHashFunction(hashName)
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

// 相手側 TA が提示したセッションの有効期限を読み取る。
func getExpirationDate(sess *http.Cookie) (expiDate time.Time) {
	if sess.MaxAge != 0 {
		return time.Now().Add(time.Duration(sess.MaxAge))
	} else {
		return sess.Expires
	}
}
