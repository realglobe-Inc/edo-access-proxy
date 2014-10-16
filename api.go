package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"github.com/realglobe-Inc/edo/util"
	"github.com/realglobe-Inc/go-lib-rg/erro"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	headerTaId       = "X-Edo-Ta-Id"
	headerTaToken    = "X-Edo-Ta-Token"
	headerTaTokenSig = "X-Edo-Ta-Token-Sign"
	headerHashFunc   = "X-Edo-Hash-Function"

	headerTaAuthErr = "X-Edo-Ta-Auth-Error"

	cookieTaSess = "X-Edo-Ta-Session"
)

// Web プロキシ。
func proxyApi(sys *system, w http.ResponseWriter, r *http.Request) error {

	uri := r.URL.Scheme + "://" + r.URL.Host + r.URL.Path
	taId := r.Header.Get(headerTaId)
	if taId == "" {
		taId = sys.taId
	}

	sess, _, err := sys.session(uri, taId, nil)
	if err != nil {
		return erro.Wrap(err)
	}

	if sess != nil {
		// セッション確立済み。
		return forward(sys, w, r, uri, taId, sess)
	} else {
		// セッション未確立。
		return startSession(sys, w, r, uri, taId)
	}
}

// 転送する。
func forward(sys *system, w http.ResponseWriter, r *http.Request, uri, taId string, sess *session) error {
	r.AddCookie(&http.Cookie{Name: cookieTaSess, Value: sess.id})
	r.RequestURI = ""

	resp, err := sess.cli.Do(r)
	if err != nil {
		err = erro.Wrap(err)
		switch erro.Unwrap(err).(type) {
		case *net.OpError:
			return erro.Wrap(util.NewHttpStatusError(http.StatusNotFound, "cannot connect "+uri, err))
		default:
			return err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized && resp.Header.Get(headerTaAuthErr) != "" {
		// edo-auth で 401 Unauthorized なら、タイミングの問題なので startSession からやり直す。
		// 古いセッションは上書きされるので消す必要無し。
		return startSession(sys, w, r, uri, taId)
	}

	return copyResponse(resp, w)
}

// セッション開始。
func startSession(sys *system, w http.ResponseWriter, r *http.Request, uri, taId string) error {

	cli := &http.Client{}

	resp, err := cli.Get(uri)
	if err != nil {
		err = erro.Wrap(err)
		switch erro.Unwrap(err).(type) {
		case *net.OpError:
			return erro.Wrap(util.NewHttpStatusError(http.StatusNotFound, "cannot connect "+uri, err))
		default:
			return err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return copyResponse(resp, w)
	}

	// 相手側 TA も認証始めた。

	sess, sessToken := parseSession(resp)
	if sess == nil {
		return erro.Wrap(util.NewHttpStatusError(http.StatusForbidden, "no cookie "+cookieTaSess, nil))
	} else if sessToken == "" {
		return erro.Wrap(util.NewHttpStatusError(http.StatusForbidden, "no header field "+headerTaToken, nil))
	}

	expiDate := getExpirationDate(sess)

	// 認証用データが揃ってた。

	priKey, _, err := sys.privateKey(taId, nil)
	if err != nil {
		return erro.Wrap(err)
	} else if priKey == nil {
		return erro.Wrap(util.NewHttpStatusError(http.StatusForbidden, "no private key of "+taId, nil))
	}

	// 秘密鍵を用意できた。

	hashName := r.Header.Get(headerHashFunc)
	if hashName == "" {
		hashName = sys.hashName
	}

	sign, err := sign(priKey, hashName, sessToken)
	if err != nil {
		return erro.Wrap(err)
	}

	// 署名できた。

	r.AddCookie(&http.Cookie{Name: cookieTaSess, Value: sess.Value})
	r.Header.Set(headerTaId, taId)
	r.Header.Set(headerTaTokenSig, sign)
	r.Header.Set(headerHashFunc, hashName)
	r.RequestURI = ""

	resp, err = cli.Do(r)
	if err != nil {
		err = erro.Wrap(err)
		switch erro.Unwrap(err).(type) {
		case *net.OpError:
			return erro.Wrap(util.NewHttpStatusError(http.StatusNotFound, "cannot connect "+uri, err))
		default:
			return err
		}
	}
	defer resp.Body.Close()

	if resp.Header.Get(headerTaAuthErr) != "" {
		// セッションを保存。
		if _, err := sys.addSession(&session{id: sess.Value, uri: uri, taId: taId, cli: cli}, expiDate); err != nil {
			return erro.Wrap(err)
		}
	}

	return copyResponse(resp, w)
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
