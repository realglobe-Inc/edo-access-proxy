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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	cryptoutil "github.com/realglobe-Inc/edo-lib/crypto"
	"github.com/realglobe-Inc/edo-lib/driver"
	logutil "github.com/realglobe-Inc/edo-lib/log"
	"github.com/realglobe-Inc/edo-lib/test"
	"github.com/realglobe-Inc/go-lib/erro"
	"github.com/realglobe-Inc/go-lib/rglog/level"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReadHead(t *testing.T) {
	original := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	head, err := readHead(strings.NewReader(original), len(original)+1)
	if err != io.EOF {
		if err == nil {
			t.Error(err)
		} else {
			t.Fatal(err)
		}
	} else if string(head) != original {
		t.Error(string(head))
	}

	head, err = readHead(strings.NewReader(original), len(original))
	if err != nil && err != io.EOF {
		t.Fatal(err)
	} else if string(head) != original {
		t.Error(string(head))
	}

	head, err = readHead(strings.NewReader(original), len(original)-1)
	if err != nil {
		t.Fatal(err)
	} else if string(head) != original[:len(original)-1] {
		t.Error(string(head))
	}
}

var testPriKey *rsa.PrivateKey

func init() {
	var err error
	testPriKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
}

func init() {
	logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
}

func newTestSystem() *system {
	return &system{
		priKeyCont: driver.NewMemoryListedKeyValueStore(0, 0),
		taId:       "ta-no-id",
		hashName:   "sha256",
		sessCont:   driver.NewMemoryConcurrentVolatileKeyValueStore(0, 0),
		cliCont:    driver.NewMemoryConcurrentVolatileKeyValueStore(0, 0),
		threSize:   8192,
	}
}

func setupAccessProxy(sys *system) (retSys *system, urlHead string, shutCh chan struct{}, err error) {
	port, err := test.FreePort()
	if err != nil {
		return nil, "", nil, erro.Wrap(err)
	}

	if sys == nil {
		sys = newTestSystem()
	}
	shutCh = make(chan struct{}, 10)
	urlHead = "http://localhost:" + strconv.Itoa(port)

	go serve(sys, "tcp", "", port, "http", shutCh)
	// 起動待ち。
	for i := time.Nanosecond; i < time.Second; i *= 2 {
		req, err := http.NewRequest("GET", urlHead+okPath, nil)
		if err != nil {
			sys.close()
			shutCh <- struct{}{}
			return nil, "", nil, erro.Wrap(err)
		}
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			// ちょっと待って再挑戦。
			time.Sleep(i)
			continue
		}
		// ちゃんとつながったので終わり。
		resp.Body.Close()
		return sys, urlHead, shutCh, nil
	}
	// 時間切れ。
	sys.close()
	shutCh <- struct{}{}
	return nil, "", nil, erro.New("time out")
}

// 正常系。事前検査無し。
func TestNormalWithoutCheck(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	dest, err := test.NewHttpServer(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// 素通りする。
	dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err := cli.Get("http://" + dest.Address() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusOK)
	} else if resp.Header.Get(headerAccProxErr) != "" {
		t.Error(headerAccProxErr + " is " + resp.Header.Get(headerAccProxErr))
	} else if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if string(buff) != "body da yo" {
		t.Error("body is " + string(buff) + " not body da yo")
	}

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	sys.priKeyCont.Put(sys.taId, testPriKey)
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":      []string{(&http.Cookie{Name: cookTaSess, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	reqCh := dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err = cli.Get("http://" + dest.Address() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusOK)
	} else if resp.Header.Get(headerAccProxErr) != "" {
		t.Error(headerAccProxErr + " is " + resp.Header.Get(headerAccProxErr))
	} else if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if string(buff) != "body da yo" {
		t.Error("body is " + string(buff) + " not body da yo")
	}

	req := <-reqCh
	if cook, err := req.Cookie(cookTaSess); err != nil {
		t.Fatal(err)
	} else if cook.Value != sessId {
		t.Error(cookTaSess + " is " + cook.Value + " not " + sessId)
	}
	if req.Header.Get(headerAuthTaId) != sys.taId {
		t.Error(headerTaId + " is " + req.Header.Get(headerTaId) + " not " + sys.taId)
	}
	if req.Header.Get(headerAuthHashFunc) != sys.hashName {
		t.Error(headerAuthHashFunc + " is " + req.Header.Get(headerAuthHashFunc) + " not " + sys.hashName)
	}
	if req.Header.Get(headerAuthTaTokenSig) == "" {
		t.Error(headerAuthTaTokenSig + " is not exist")
	}
	rawSig, err := base64.StdEncoding.DecodeString(req.Header.Get(headerAuthTaTokenSig))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := cryptoutil.ParseHashFunction(req.Header.Get(headerAuthHashFunc))
	if err != nil {
		t.Fatal(err)
	}
	h := hash.New()
	h.Write([]byte(token))
	if err := rsa.VerifyPKCS1v15(&testPriKey.PublicKey, hash, h.Sum(nil), rawSig); err != nil {
		t.Fatal(err)
	}

	// 認証済み。
	reqCh = dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err = cli.Get("http://" + dest.Address() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusOK)
	} else if resp.Header.Get(headerAccProxErr) != "" {
		t.Error(headerAccProxErr + " is " + resp.Header.Get(headerAccProxErr))
	} else if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if string(buff) != "body da yo" {
		t.Error("body is " + string(buff) + " not body da yo")
	}

	req = <-reqCh
	if cook, err := req.Cookie(cookTaSess); err != nil {
		t.Fatal(err)
	} else if cook.Value != sessId {
		t.Error(cookTaSess + " is " + cook.Value + " not " + sessId)
	}
}

// 正常系。事前検査あり。
func TestNormalWithCheck(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	dest, err := test.NewHttpServer(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	sys := newTestSystem()
	sys.threSize = 1
	_, urlHead, shutCh, err := setupAccessProxy(sys)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// 素通りする。
	dest.AddResponse(http.StatusOK, nil, nil)
	dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err := cli.Post("http://"+dest.Address()+"/", "text/plain", strings.NewReader("oi"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusOK)
	} else if resp.Header.Get(headerAccProxErr) != "" {
		t.Error(headerAccProxErr + " is " + resp.Header.Get(headerAccProxErr))
	} else if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if string(buff) != "body da yo" {
		t.Error("body is " + string(buff) + " not body da yo")
	}

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	sys.priKeyCont.Put(sys.taId, testPriKey)
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":      []string{(&http.Cookie{Name: cookTaSess, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	reqCh := dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err = cli.Post("http://"+dest.Address()+"/", "text/plain", strings.NewReader("oi"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusOK)
	} else if resp.Header.Get(headerAccProxErr) != "" {
		t.Error(headerAccProxErr + " is " + resp.Header.Get(headerAccProxErr))
	} else if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if string(buff) != "body da yo" {
		t.Error("body is " + string(buff) + " not body da yo")
	}

	req := <-reqCh
	if cook, err := req.Cookie(cookTaSess); err != nil {
		t.Fatal(err)
	} else if cook.Value != sessId {
		t.Error(cookTaSess + " is " + cook.Value + " not " + sessId)
	}
	if req.Header.Get(headerAuthTaId) != sys.taId {
		t.Error(headerTaId + " is " + req.Header.Get(headerTaId) + " not " + sys.taId)
	}
	if req.Header.Get(headerAuthHashFunc) != sys.hashName {
		t.Error(headerAuthHashFunc + " is " + req.Header.Get(headerAuthHashFunc) + " not " + sys.hashName)
	}
	if req.Header.Get(headerAuthTaTokenSig) == "" {
		t.Error(headerAuthTaTokenSig + " is not exist")
	}
	rawSig, err := base64.StdEncoding.DecodeString(req.Header.Get(headerAuthTaTokenSig))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := cryptoutil.ParseHashFunction(req.Header.Get(headerAuthHashFunc))
	if err != nil {
		t.Fatal(err)
	}
	h := hash.New()
	h.Write([]byte(token))
	if err := rsa.VerifyPKCS1v15(&testPriKey.PublicKey, hash, h.Sum(nil), rawSig); err != nil {
		t.Fatal(err)
	}

	// 認証済み。
	dest.AddResponse(http.StatusOK, nil, nil)
	reqCh = dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err = cli.Post("http://"+dest.Address()+"/", "text/plain", strings.NewReader("oi"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusOK)
	} else if resp.Header.Get(headerAccProxErr) != "" {
		t.Error(headerAccProxErr + " is " + resp.Header.Get(headerAccProxErr))
	} else if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if string(buff) != "body da yo" {
		t.Error("body is " + string(buff) + " not body da yo")
	}

	req = <-reqCh
	if cook, err := req.Cookie(cookTaSess); err != nil {
		t.Fatal(err)
	} else if cook.Value != sessId {
		t.Error(cookTaSess + " is " + cook.Value + " not " + sessId)
	}
}

// セッション期限の通知が Max-Age でも大丈夫なことの検査。
func TestNormalMaxAge(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	dest, err := test.NewHttpServer(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	sys.priKeyCont.Put(sys.taId, testPriKey)
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":      []string{(&http.Cookie{Name: cookTaSess, Value: sessId, MaxAge: 10}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err := cli.Get("http://" + dest.Address() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get(headerAccProxErr) != "" {
		t.Error(headerAccProxErr + " is " + resp.Header.Get(headerAccProxErr))
	}

	//time.Sleep(10 * time.Millisecond)

	// 認証済み。
	reqCh := dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err = cli.Get("http://" + dest.Address() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req := <-reqCh
	if cook, err := req.Cookie(cookTaSess); err != nil {
		t.Fatal(err)
	} else if cook.Value != sessId {
		t.Error(cookTaSess + " is " + cook.Value + " not " + sessId)
	}
}

// ボディがちゃんと転送されるかどうか。
func TestEdoAccessProxyBody(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	dest, err := test.NewHttpServer(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	sessId := "session-da-yo"
	token := "token-da-yo"
	sys.priKeyCont.Put(sys.taId, testPriKey)
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":      []string{(&http.Cookie{Name: cookTaSess, Value: sessId}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	reqCh := dest.AddResponse(http.StatusOK, nil, nil)

	body := "body da yo"
	resp, err := cli.Post("http://"+dest.Address()+"/", "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req := <-reqCh
	buff, err := ioutil.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(buff) != body {
		t.Error("body is " + string(buff) + " not " + body)
	}
}

// Web プロキシ方式の URL 指定じゃなかったらちゃんとエラーを返すか。
func TestNotProxyUrl(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	cli := &http.Client{}

	resp, err := cli.Get(urlHead + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get(headerAccProxErr) == "" {
		t.Error("no " + headerAccProxErr)
	}
}

// ヘッダフィールドで TA を指定できるか。
func TestSpecifyTa(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	dest, err := test.NewHttpServer(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	taId := "chigau-ta-no-id"
	sys.priKeyCont.Put(taId, testPriKey)
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":      []string{(&http.Cookie{Name: cookTaSess, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	reqCh := dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	req, err := http.NewRequest("GET", "http://"+dest.Address()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerTaId, taId)

	resp, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req = <-reqCh
	if req.Header.Get(headerAuthTaId) != taId {
		t.Error(headerAuthTaId + " is " + req.Header.Get(headerAuthTaId) + " not " + taId)
	}

	// 認証済み。
	reqCh = dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	req, err = http.NewRequest("GET", "http://"+dest.Address()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerTaId, taId)

	resp, err = cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req = <-reqCh
	if req.Header.Get(headerAuthTaId) != "" {
		t.Error(headerAuthTaId + " is " + req.Header.Get(headerAuthTaId) + " not empty")
	}
}

// ヘッダフィールドで宛先を指定できるか。
func TestSpecifyDestination(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	dest, err := test.NewHttpServer(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	cli := &http.Client{}

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	taId := "chigau-ta-no-id"
	sys.priKeyCont.Put(taId, testPriKey)
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":      []string{(&http.Cookie{Name: cookTaSess, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	reqCh := dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	req, err := http.NewRequest("GET", urlHead, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerTaId, taId)
	req.Header.Set(headerAccProxUri, "http://"+dest.Address()+"/")

	resp, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req = <-reqCh
	if req.Header.Get(headerTaId) != taId {
		t.Error(headerTaId + " is " + req.Header.Get(headerTaId) + " not " + taId)
	}

	// 認証済み。
	reqCh = dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	req, err = http.NewRequest("GET", urlHead, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerTaId, taId)
	req.Header.Set(headerAccProxUri, "http://"+dest.Address()+"/")

	resp, err = cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req = <-reqCh
	if req.Header.Get(headerTaId) != taId {
		t.Error(headerTaId + " is " + req.Header.Get(headerTaId) + " not " + taId)
	}
}

// プロキシ先に届かないときに 404 を返すか。
func TestNoDestination(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	unusedPort, err := test.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := cli.Get("http://localhost:" + strconv.Itoa(unusedPort) + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusNotFound)
	} else if resp.Header.Get(headerAccProxErr) == "" {
		t.Error("no " + headerAccProxErr)
	}
}

// プロキシ先から認証開始 (401 Unauthorized) 以外のエラーが返ったら中断してそのまま返すか。
func TestErrorCancel(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	dest, err := test.NewHttpServer(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	dest.AddResponse(http.StatusInternalServerError, map[string][]string{headerAuthTaErr: []string{"okashii yo"}}, []byte("okashii yo"))

	resp, err := cli.Get("http://" + dest.Address() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusInternalServerError)
	} else if resp.Header.Get(headerAuthTaErr) == "" {
		t.Error("no " + headerAuthTaErr)
	}
	buff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	} else if string(buff) != "okashii yo" {
		t.Error("body is " + string(buff) + " not okashii yo")
	}
}

// プロキシ先から返された認証開始情報が足りなかったら 403 Forbidden を返すか。
func TestLackOfAuthenticationInformation(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	dest, err := test.NewHttpServer(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// X-Edo-Auth-Ta-Token が無い。
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":    []string{(&http.Cookie{Name: cookTaSess, Value: "session-da-yo", Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr: []string{"start new session"},
	}, nil)

	resp, err := cli.Get("http://" + dest.Address() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusForbidden)
	} else if resp.Header.Get(headerAccProxErr) == "" {
		t.Error("no " + headerAccProxErr)
	}

	// X-Edo-Auth-Ta-Session が無い。
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{"token-da-yo"},
	}, nil)

	resp, err = cli.Get("http://" + dest.Address() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusForbidden)
	} else if resp.Header.Get(headerAccProxErr) == "" {
		t.Error("no " + headerAccProxErr)
	}
}

// 署名用の鍵が無かったら 403 Forbidden を返すか。
func TestNoSignKey(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	dest, err := test.NewHttpServer(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":      []string{(&http.Cookie{Name: cookTaSess, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err := cli.Get("http://" + dest.Address() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Error("status is ", resp.StatusCode, " not ", http.StatusForbidden)
	} else if resp.Header.Get(headerAccProxErr) == "" {
		t.Error("no " + headerAccProxErr)
	}
}

// 全部読んだらメモリから溢れるようなリクエストの転送。
func TestBigRequest(t *testing.T) {
	// リクエストを全部捨てて一言返すだけのプロキシ先を用意。
	destLis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLis.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		buff := make([]byte, 8192)
		for {
			_, err := r.Body.Read(buff)
			if err != nil {
				if err == io.EOF {
					w.Write([]byte("zenbu yonda"))
					return
				} else {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("zenbu yomenakatta"))
					return
				}
			}
		}
	})
	go func() {
		http.Serve(destLis, mux)
	}()

	// テストするプロキシサーバーを用意。
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	errCh := make(chan error, 1)
	rPipe, wPipe := io.Pipe()
	go func() {
		defer wPipe.Close()
		buff := make([]byte, (1 << 21) /* 2 MB */)
		for n := 0; n < (1 << 32); /* 4 GB */ {
			l, err := wPipe.Write(buff)
			if err != nil {
				errCh <- err
				return
			}
			n += l
		}
		errCh <- nil
	}()

	resp, err := cli.Post("http://"+destLis.Addr().String()+"/", "text/plain", rPipe)
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
	} else if string(buff) != "zenbu yonda" {
		t.Error(buff)
	}
}

// 全部読んだらメモリから溢れるようなレスポンスの処理。
func TestBigResponse(t *testing.T) {
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
		for n := 0; n < (1 << 32); { /* 4 GB */
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
	sys, urlHead, shutCh, err := setupAccessProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.close()
	defer func() { shutCh <- struct{}{} }()

	proxyUrl, err := url.Parse(urlHead)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	resp, err := cli.Get("http://" + destLis.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	buff := make([]byte, 8192)
	for {
		_, err := resp.Body.Read(buff)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				t.Fatal(err)
			}
		}
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
