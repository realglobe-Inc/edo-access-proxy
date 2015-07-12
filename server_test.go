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
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/realglobe-Inc/edo-lib/hash"
	"github.com/realglobe-Inc/edo-lib/jwk"
	logutil "github.com/realglobe-Inc/edo-lib/log"
	"github.com/realglobe-Inc/edo-lib/test"
	"github.com/realglobe-Inc/go-lib/erro"
	"github.com/realglobe-Inc/go-lib/rglog/level"
)

func init() {
	logutil.SetupConsole(logRoot, level.OFF)
}

type testServer struct {
	uri       string
	shutCh    chan struct{}
	keyDbPath string
}

func (serv *testServer) close() {
	serv.shutCh <- struct{}{}
	os.RemoveAll(serv.keyDbPath)
}

func newTestServer(param *parameters) (*parameters, *testServer, error) {
	failed := false

	// 環境設定。
	if param == nil {
		var err error
		param, err = newTestParameter()
		if nil != err {
			failed = true
			return nil, nil, erro.Wrap(err)
		}
	}
	var err error
	param.socPort, err = test.FreePort()
	if err != nil {
		failed = true
		return nil, nil, erro.Wrap(err)
	}

	// 鍵の準備。
	keyDbPath, err := setupKeyDb(param.keyDbPath, []jwk.Key{test_key})
	if err != nil {
		failed = true
		return nil, nil, erro.Wrap(err)
	}
	defer func() {
		if failed {
			os.RemoveAll(keyDbPath)
		}
	}()
	param.keyDbPath = keyDbPath

	// テストするプロキシサーバーを用意。
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(param)
	}()
	defer func() {
		if failed {
			param.shutCh <- struct{}{}
		}
	}()

	uri := "http://localhost:" + strconv.Itoa(param.socPort)
	exp := time.Now().Add(time.Minute)
	for {
		if time.Now().After(exp) {
			failed = true
			return nil, nil, erro.New("timeout")
		}
		r, err := http.NewRequest("GET", uri+param.pathOk, nil)
		if err != nil {
			failed = true
			return nil, nil, erro.Wrap(err)
		}
		r.Header.Set("Connection", "close")
		if _, err := http.DefaultClient.Do(r); err == nil {
			break
		}

		select {
		case err := <-errCh:
			failed = true
			return nil, nil, erro.Wrap(err)
		default:
		}
		time.Sleep(time.Millisecond)
	}
	return param, &testServer{
		uri,
		param.shutCh,
		keyDbPath,
	}, nil
}

// 正常系。事前検査無し。
func TestNormalWithoutCheck(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole(logRoot, level.ALL)
	// defer logutil.SetupConsole(logRoot, level.OFF)
	// ////////////////////////////////

	// 連携先 TA の準備。
	toTaServ, err := test.NewHttpServer(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.Close()

	param, serv, err := newTestServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serv.close()

	// 素通りする。
	toTaServ.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	r, err := newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusOK)
	} else if resp.Header.Get("X-Edo-Access-Proxy-Error") != "" {
		t.Error("X-Edo-Access-Proxy-Error" + " is " + resp.Header.Get("X-Edo-Access-Proxy-Error"))
	} else if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if string(buff) != "body da yo" {
		t.Error("body is " + string(buff) + " not body da yo")
	}

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	toTaServ.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":          []string{(&http.Cookie{Name: param.sessLabel, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		"X-Edo-Auth-Ta-Error": []string{"start new session"},
		"X-Edo-Auth-Ta-Token": []string{token},
	}, nil)
	reqCh := toTaServ.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	r, err = newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusOK)
	} else if resp.Header.Get("X-Edo-Access-Proxy-Error") != "" {
		t.Error("X-Edo-Access-Proxy-Error" + " is " + resp.Header.Get("X-Edo-Access-Proxy-Error"))
	} else if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if string(buff) != "body da yo" {
		t.Error("body is " + string(buff) + " not body da yo")
	}

	req := <-reqCh
	if cook, err := req.Cookie(param.sessLabel); err != nil {
		t.Fatal(err)
	} else if cook.Value != sessId {
		t.Error(param.sessLabel + " is " + cook.Value + " not " + sessId)
	}
	if req.Header.Get("X-Edo-Auth-Ta-Id") != param.selfId {
		t.Error("X-Edo-Auth-Ta-Id" + " is " + req.Header.Get("X-Edo-Auth-Ta-Id") + " not " + param.selfId)
	}
	if req.Header.Get("X-Edo-Auth-Hash-Function") != param.hashAlg {
		t.Error("X-Edo-Auth-Hash-Function" + " is " + req.Header.Get("X-Edo-Auth-Hash-Function") + " not " + param.hashAlg)
	}
	if req.Header.Get("X-Edo-Auth-Ta-Token-Sign") == "" {
		t.Error("X-Edo-Auth-Ta-Token-Sign" + " is not exist")
	}
	rawSig, err := base64.StdEncoding.DecodeString(req.Header.Get("X-Edo-Auth-Ta-Token-Sign"))
	if err != nil {
		t.Fatal(err)
	}
	hGen := hash.Generator(req.Header.Get("X-Edo-Auth-Hash-Function"))
	if hGen == 0 {
		t.Fatal("no hash algorithm")
	}
	hFun := hGen.New()
	hFun.Write([]byte(token))
	if err := rsa.VerifyPKCS1v15(test_key.Public().(*rsa.PublicKey), hGen, hFun.Sum(nil), rawSig); err != nil {
		t.Fatal(err)
	}

	// 認証済み。
	reqCh = toTaServ.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	r, err = newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusOK)
	} else if resp.Header.Get("X-Edo-Access-Proxy-Error") != "" {
		t.Error("X-Edo-Access-Proxy-Error" + " is " + resp.Header.Get("X-Edo-Access-Proxy-Error"))
	} else if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if string(buff) != "body da yo" {
		t.Error("body is " + string(buff) + " not body da yo")
	}

	req = <-reqCh
	if cook, err := req.Cookie(param.sessLabel); err != nil {
		t.Fatal(err)
	} else if cook.Value != sessId {
		t.Error(param.sessLabel + " is " + cook.Value + " not " + sessId)
	}
}

// セッション期限の通知が Max-Age でも大丈夫なことの検査。
func TestNormalMaxAge(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole(logRoot, level.ALL)
	// defer logutil.SetupConsole(logRoot, level.OFF)
	// ////////////////////////////////

	// 連携先 TA の準備。
	toTaServ, err := test.NewHttpServer(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.Close()

	param, serv, err := newTestServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serv.close()

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	toTaServ.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":          []string{(&http.Cookie{Name: param.sessLabel, Value: sessId, MaxAge: 10}).String()},
		"X-Edo-Auth-Ta-Error": []string{"start new session"},
		"X-Edo-Auth-Ta-Token": []string{token},
	}, nil)
	toTaServ.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	r, err := newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-Edo-Access-Proxy-Error") != "" {
		t.Error("X-Edo-Access-Proxy-Error" + " is " + resp.Header.Get("X-Edo-Access-Proxy-Error"))
	}

	//time.Sleep(10 * time.Millisecond)

	// 認証済み。
	reqCh := toTaServ.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	r, err = newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req := <-reqCh
	if cook, err := req.Cookie(param.sessLabel); err != nil {
		t.Fatal(err)
	} else if cook.Value != sessId {
		t.Error(param.sessLabel + " is " + cook.Value + " not " + sessId)
	}
}

// ボディがちゃんと転送されるかどうか。
func TestEdoAccessProxyBody(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole(logRoot, level.ALL)
	// defer logutil.SetupConsole(logRoot, level.OFF)
	// ////////////////////////////////

	// 連携先 TA の準備。
	toTaServ, err := test.NewHttpServer(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.Close()

	param, serv, err := newTestServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serv.close()

	sessId := "session-da-yo"
	token := "token-da-yo"
	toTaServ.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":          []string{(&http.Cookie{Name: param.sessLabel, Value: sessId}).String()},
		"X-Edo-Auth-Ta-Error": []string{"start new session"},
		"X-Edo-Auth-Ta-Token": []string{token},
	}, nil)
	reqCh := toTaServ.AddResponse(http.StatusOK, nil, nil)

	body := []byte("body da yo")
	r, err := newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", body)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req := <-reqCh
	buff, err := ioutil.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buff, body) {
		t.Error("body is ", buff, " not ", body)
	}
}

// 宛先指定がなかったらちゃんとエラーを返すか。
func TestNotToUri(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole(logRoot, level.ALL)
	// defer logutil.SetupConsole(logRoot, level.OFF)
	// ////////////////////////////////

	// 連携先 TA の準備。
	toTaServ, err := test.NewHttpServer(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.Close()

	param, serv, err := newTestServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serv.close()

	toTaServ.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	r, err := newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Del("X-Edo-Access-Proxy-Uri")
	r.Header.Set("Connection", "close")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusBadRequest)
	} else if resp.Header.Get("X-Edo-Access-Proxy-Error") == "" {
		t.Error("no " + "X-Edo-Access-Proxy-Error")
	}
}

// プロキシ先に届かないときに 404 を返すか。
func TestNoDestination(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole(logRoot, level.ALL)
	// defer logutil.SetupConsole(logRoot, level.OFF)
	// ////////////////////////////////

	param, serv, err := newTestServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serv.close()

	port, err := test.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	r, err := newTestRequest(serv.uri+param.pathProx, "http://localhost:"+strconv.Itoa(port)+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusNotFound)
	} else if resp.Header.Get("X-Edo-Access-Proxy-Error") == "" {
		t.Error("no " + "X-Edo-Access-Proxy-Error")
	}
}

// プロキシ先から認証開始 (401 Unauthorized) 以外のエラーが返ったら中断してそのまま返すか。
func TestErrorCancel(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole(logRoot, level.ALL)
	// defer logutil.SetupConsole(logRoot, level.OFF)
	// ////////////////////////////////

	// 連携先 TA の準備。
	toTaServ, err := test.NewHttpServer(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.Close()

	param, serv, err := newTestServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serv.close()

	toTaServ.AddResponse(http.StatusInternalServerError, map[string][]string{"X-Edo-Auth-Ta-Error": []string{"okashii yo"}}, []byte("okashii yo"))

	r, err := newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusInternalServerError)
	} else if resp.Header.Get("X-Edo-Auth-Ta-Error") == "" {
		t.Error("no " + "X-Edo-Auth-Ta-Error")
	}
	buff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	} else if string(buff) != "okashii yo" {
		t.Error("body is " + string(buff) + " not okashii yo")
	}
}

// プロキシ先から返された認証開始情報が足りなかったらそのまま返すか。
func TestLackOfAuthenticationInformation(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole(logRoot, level.ALL)
	// defer logutil.SetupConsole(logRoot, level.OFF)
	// ////////////////////////////////

	// 連携先 TA の準備。
	toTaServ, err := test.NewHttpServer(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.Close()

	param, serv, err := newTestServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serv.close()

	// X-Edo-Auth-Ta-Token が無い。
	toTaServ.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":          []string{(&http.Cookie{Name: param.sessLabel, Value: "session-da-yo", Expires: time.Now().Add(10 * time.Second)}).String()},
		"X-Edo-Auth-Ta-Error": []string{"start new session"},
	}, nil)

	r, err := newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusForbidden)
	} else if resp.Header.Get("X-Edo-Access-Proxy-Error") == "" {
		t.Error("no " + "X-Edo-Access-Proxy-Error")
	}

	// X-Edo-Auth-Ta-Session が無い。
	toTaServ.AddResponse(http.StatusUnauthorized, map[string][]string{
		"X-Edo-Auth-Ta-Error": []string{"start new session"},
		"X-Edo-Auth-Ta-Token": []string{"token-da-yo"},
	}, nil)

	r, err = newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusForbidden)
	} else if resp.Header.Get("X-Edo-Access-Proxy-Error") == "" {
		t.Error("no " + "X-Edo-Access-Proxy-Error")
	}
}

// 署名用の鍵が無かったら 403 Forbidden を返すか。
func TestNoSignKey(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole(logRoot, level.ALL)
	// defer logutil.SetupConsole(logRoot, level.OFF)
	// ////////////////////////////////

	// 連携先 TA の準備。
	toTaServ, err := test.NewHttpServer(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.Close()

	param, serv, err := newTestServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serv.close()

	if err := os.RemoveAll(param.keyDbPath); err != nil {
		t.Fatal(err)
	}

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	toTaServ.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":          []string{(&http.Cookie{Name: param.sessLabel, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		"X-Edo-Auth-Ta-Error": []string{"start new session"},
		"X-Edo-Auth-Ta-Token": []string{token},
	}, nil)
	toTaServ.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	r, err := newTestRequest(serv.uri+param.pathProx, toTaServ.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusForbidden)
	} else if resp.Header.Get("X-Edo-Access-Proxy-Error") == "" {
		t.Error("no " + "X-Edo-Access-Proxy-Error")
	}
}

// 全部読んだらメモリから溢れるようなリクエストの転送。
func TestBigRequest(t *testing.T) {
	size := (1 << 32) // 4 GB

	// リクエストを全部捨てて一言返すだけのプロキシ先を用意。
	destLis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLis.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		buff := make([]byte, 8192)
		for sum := 0; ; {
			s, err := r.Body.Read(buff)
			if err != nil {
				if err == io.EOF {
					w.Write([]byte(strconv.Itoa(sum + s)))
					return
				} else {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("zenbu yomenakatta"))
					return
				}
			}
			sum += s
		}
	})
	go func() {
		http.Serve(destLis, mux)
	}()

	param, serv, err := newTestServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serv.close()

	errCh := make(chan error, 1)
	rPipe, wPipe := io.Pipe()
	go func() {
		defer wPipe.Close()
		buff := make([]byte, (1 << 21) /* 2 MB */)
		for n := 0; n < size; /* 4 GB */ {
			l, err := wPipe.Write(buff)
			if err != nil {
				errCh <- err
				return
			}
			n += l
		}
		errCh <- nil
	}()

	r, err := newTestRequest(serv.uri+param.pathProx, "http://"+destLis.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	r.Body = rPipe
	r.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Error(resp)
	} else if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if string(buff) != strconv.Itoa(size) {
		t.Error(string(buff))
	}
}

// 全部読んだらメモリから溢れるようなレスポンスの処理。
func TestBigResponse(t *testing.T) {
	size := (1 << 32) // 4 GB

	// リクエストを無視して巨大な返答を返すプロキシ先を用意。
	errCh := make(chan error, 100)
	destLis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLis.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		buff := make([]byte, (1 << 21) /* 2 MB */)
		for n := 0; n < size; { /* 4 GB */
			l, err := w.Write(buff)
			if err != nil {
				errCh <- err
				return
			}
			n += l
		}
	})
	go func() {
		http.Serve(destLis, mux)
	}()

	// テストするプロキシサーバーを用意。
	param, serv, err := newTestServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serv.close()

	r, err := newTestRequest(serv.uri+param.pathProx, "http://"+destLis.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	buff := make([]byte, 8192)
	for sum := 0; ; {
		s, err := resp.Body.Read(buff)
		if err != nil {
			if err == io.EOF {
				if sum+s != size {
					t.Fatal("read ", sum+s, " bytes not ", size, "bytes")
				}
				break
			} else {
				t.Fatal(err)
			}
		}
		sum += s
	}

	if resp.StatusCode != http.StatusOK {
		t.Error(resp)
	}

	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

func setupKeyDb(path string, keys []jwk.Key) (dir string, err error) {
	dir, err = ioutil.TempDir(filepath.Dir(path), filepath.Base(path))
	for i, key := range keys {
		if data, err := json.Marshal(key.ToMap()); err != nil {
			return "", erro.Wrap(err)
		} else if ioutil.WriteFile(filepath.Join(dir, strconv.Itoa(i)+".json"), data, 0644); err != nil {
			return "", erro.Wrap(err)
		}
	}
	return dir, nil
}
