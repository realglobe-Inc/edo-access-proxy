package main

import (
	"crypto/rsa"
	"encoding/base64"
	"github.com/realglobe-Inc/edo/driver"
	"github.com/realglobe-Inc/edo/util"
	"github.com/realglobe-Inc/go-lib-rg/rglog/level"
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
	testPriKey, err = util.ParseRsaPrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzq6SrcupWm+rwSKsIVeOyoRfUc0uPvoxPAEGF5uxZ9y+oqoP
nTFCUAhDTX1lXDv4eHDPVsLuh8q75Bk0uDsYzMNtrODC/neW6U3aKXHOXpdmzrDi
hk8/elgIxnZR5Dm5Vl5EeyCENwQIdxg+knU9dkX7XwFib/RZAK2SXv1Xtgj4x6q7
VgPl3zghdr67jCjZo3zgl0SxbZcOe4Yu4YGi79+UZ14/tD9EghQGmFtFRac2xIH5
iAYDhvDVi6zJgRjevSdds1xqKI3hkQJNT3zju3wa4HhSwmMLXwPTUXeTukTU1gU5
7++SWzrUogi71aQPcv8Y1k78Li5bS/VN1WTN5QIDAQABAoIBAAFQqQxEDHrP1Rbw
gonfxb/SIc0ichXif6ezFffWfMV9aRUd4eWNJ6/crZjzoE567zTM+vTBXsUsbA+i
fWxiq+C5qZv8/iCiYCpx3V6AI+EEM5pDE93o6S19G+kvXYwHNf+vr93cshqrguZH
GDbUWiTDgzryhk7SDjLr58+E6yb0Wrnszoj/hj8kUgra2XDkJNCHt3d8u6kQwH6T
XocD7vaFwvvf3bSs1rMqmfEkI00cidsKFXGBrcYtdMXHPLsrBhta68MfQ4VAOUOd
jdmpuR9Ok6uf+F/ur/WpmT6KFd8oCqkq/LF1S+qZsatqhX/VmzIOHrBhqWljoqug
F4QnqA0CgYEA9X5PupZPGU9i4a7XefrNtCG6GziEFjcE8Dp1qC2YXSOlDTgSahc8
ez1Y09JfLVLrDtOzEP7v6kq7PqPNC5YaUJMMThrjf/cJbNsbipyveXe58BXhf75i
7IWCiVSFP+eaf/t4VXCYiDG1E6Poc/BeLiZg+rRXJKiPC2joQiXFJOsCgYEA14cI
dOW7ZtucCuCGsNg14PMCAWhzxuymCJD01kZaPsPNjik/0F6r/qzpLMrY1EPejhvR
rnc1PFDw3L9ZmNWocHbTxoOVX798xdhkU3Kal6zr7UbRwn/40eVwxUyNZN0nrlsS
z1nl2boHvKCx1EMi3nAH3fp2byBMZdPZY+/6ZG8CgYEAm4/8A9elrfsxRKOfpYs5
eJD6tq8cfFtHBNd2oSiraTHiMDs85/9rcwjP1gJ0D2uAyjd6PCXgb84FU09G6rWm
XTKhVIkTao5naZR6ol5hj44/xBSJfYJue0SrEEz/1xvzOnBms3WTIpKlFRoDfhxu
Ab6OK6/FnNQ3ONq0et4mTBsCgYByU4K835AFA8FGU8uey1HpPX522L1xa9629I2r
jC4a1SqYmnDrSwzZT0dxJzjVgBryLvePIFTw5c6eijIwzEVJQv8bcnkuDRlWqW6u
hUBT7LpJZyOllNScIqUrQ2xNcLK33j+gFgPC9tdby7II8oPwkmTZ7x4b3HoqGbJb
PNUJqQKBgQDrLYGZ7cu0MbLpN4qQ5XOrh8SMyBdOnPdX+kzyTA2UpHuJnbRehJos
J/Bva8S1mcVghERCZLtJUEVCwEsTfM+GHqKyJvKosbVeGW/tpZpyhtfGp3tGrmxn
D8/JxZKNMEyxS8BvCPYqhobhlCqwHtc6wpSWC++fU79xvFrb/X+nVQ==
-----END RSA PRIVATE KEY-----`)
	if err != nil {
		panic(err)
	}
}

func init() {
	util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
}

func newTestSystem() *system {
	return &system{
		priKeyCont: driver.NewMemoryKeyValueStore(0),
		taId:       "ta-no-id",
		hashName:   "sha256",
		sessCont:   driver.NewMemoryTimeLimitedKeyValueStore(0),
		cliCont:    driver.NewMemoryTimeLimitedKeyValueStore(0),
		threSize:   8192,
	}
}

// 正常系。事前検査無し。
func TestNormalWithoutCheck(t *testing.T) {
	// ////////////////////////////////
	// util.SetupConsoleLog("github.com/realglobe-Inc", level.ALL)
	// defer util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	destPort, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	dest, err := util.NewTestHttpServer(destPort)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// 素通りする。
	dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err := cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
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
		"Set-Cookie":      []string{(&http.Cookie{Name: cookieTaSess, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	reqCh := dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err = cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
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
	if cookie, err := req.Cookie(cookieTaSess); err != nil {
		t.Fatal(err)
	} else if cookie.Value != sessId {
		t.Error(cookieTaSess + " is " + cookie.Value + " not " + sessId)
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
	hash, err := util.ParseHashFunction(req.Header.Get(headerAuthHashFunc))
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

	resp, err = cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
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
	if cookie, err := req.Cookie(cookieTaSess); err != nil {
		t.Fatal(err)
	} else if cookie.Value != sessId {
		t.Error(cookieTaSess + " is " + cookie.Value + " not " + sessId)
	}
}

// 正常系。事前検査あり。
func TestNormalWithCheck(t *testing.T) {
	// ////////////////////////////////
	// util.SetupConsoleLog("github.com/realglobe-Inc", level.ALL)
	// defer util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	destPort, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	dest, err := util.NewTestHttpServer(destPort)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	sys.threSize = 1
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// 素通りする。
	dest.AddResponse(http.StatusOK, nil, nil)
	dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err := cli.Post("http://localhost:"+strconv.Itoa(destPort)+"/", "text/plain", strings.NewReader("oi"))
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
		"Set-Cookie":      []string{(&http.Cookie{Name: cookieTaSess, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	reqCh := dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err = cli.Post("http://localhost:"+strconv.Itoa(destPort)+"/", "text/plain", strings.NewReader("oi"))
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
	if cookie, err := req.Cookie(cookieTaSess); err != nil {
		t.Fatal(err)
	} else if cookie.Value != sessId {
		t.Error(cookieTaSess + " is " + cookie.Value + " not " + sessId)
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
	hash, err := util.ParseHashFunction(req.Header.Get(headerAuthHashFunc))
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

	resp, err = cli.Post("http://localhost:"+strconv.Itoa(destPort)+"/", "text/plain", strings.NewReader("oi"))
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
	if cookie, err := req.Cookie(cookieTaSess); err != nil {
		t.Fatal(err)
	} else if cookie.Value != sessId {
		t.Error(cookieTaSess + " is " + cookie.Value + " not " + sessId)
	}
}

// セッション期限の通知が Max-Age でも大丈夫なことの検査。
func TestNormalMaxAge(t *testing.T) {
	// ////////////////////////////////
	// util.SetupConsoleLog("github.com/realglobe-Inc", level.ALL)
	// defer util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	destPort, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	dest, err := util.NewTestHttpServer(destPort)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	sys.priKeyCont.Put(sys.taId, testPriKey)
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":      []string{(&http.Cookie{Name: cookieTaSess, Value: sessId, MaxAge: 10}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err := cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get(headerAccProxErr) != "" {
		t.Error(headerAccProxErr + " is " + resp.Header.Get(headerAccProxErr))
	}

	time.Sleep(10 * time.Millisecond)

	// 認証済み。
	reqCh := dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err = cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req := <-reqCh
	if cookie, err := req.Cookie(cookieTaSess); err != nil {
		t.Fatal(err)
	} else if cookie.Value != sessId {
		t.Error(cookieTaSess + " is " + cookie.Value + " not " + sessId)
	}
}

// ボディがちゃんと転送されるかどうか。
func TestEdoAccessProxyBody(t *testing.T) {
	// ////////////////////////////////
	// util.SetupConsoleLog("github.com/realglobe-Inc", level.ALL)
	// defer util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	destPort, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	dest, err := util.NewTestHttpServer(destPort)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	sessId := "session-da-yo"
	token := "token-da-yo"
	sys.priKeyCont.Put(sys.taId, testPriKey)
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":      []string{(&http.Cookie{Name: cookieTaSess, Value: sessId}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	reqCh := dest.AddResponse(http.StatusOK, nil, nil)

	body := "body da yo"
	resp, err := cli.Post("http://localhost:"+strconv.Itoa(destPort)+"/", "text/plain", strings.NewReader(body))
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
	// util.SetupConsoleLog("github.com/realglobe-Inc", level.ALL)
	// defer util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// テストするプロキシサーバーを用意。
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	cli := &http.Client{}

	resp, err := cli.Get("http://localhost:" + strconv.Itoa(port) + "/")
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
	// util.SetupConsoleLog("github.com/realglobe-Inc", level.ALL)
	// defer util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	destPort, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	dest, err := util.NewTestHttpServer(destPort)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
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
		"Set-Cookie":      []string{(&http.Cookie{Name: cookieTaSess, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	reqCh := dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	req, err := http.NewRequest("GET", "http://localhost:"+strconv.Itoa(destPort)+"/", nil)
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
	if req.Header.Get(headerTaId) != taId {
		t.Error(headerTaId + " is " + req.Header.Get(headerTaId) + " not " + taId)
	}

	// 認証済み。
	reqCh = dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	req, err = http.NewRequest("GET", "http://localhost:"+strconv.Itoa(destPort)+"/", nil)
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
	if req.Header.Get(headerTaId) != taId {
		t.Error(headerTaId + " is " + req.Header.Get(headerTaId) + " not " + taId)
	}
}

// プロキシ先に届かないときに 404 を返すか。
func TestNoDestination(t *testing.T) {
	// ////////////////////////////////
	// util.SetupConsoleLog("github.com/realglobe-Inc", level.ALL)
	// defer util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// テストするプロキシサーバーを用意。
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	unusedPort, err := util.FreePort()
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
	// util.SetupConsoleLog("github.com/realglobe-Inc", level.ALL)
	// defer util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	destPort, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	dest, err := util.NewTestHttpServer(destPort)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	dest.AddResponse(http.StatusInternalServerError, map[string][]string{headerAuthTaErr: []string{"okashii yo"}}, []byte("okashii yo"))

	resp, err := cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
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
	// util.SetupConsoleLog("github.com/realglobe-Inc", level.ALL)
	// defer util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	destPort, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	dest, err := util.NewTestHttpServer(destPort)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// X-Edo-Auth-Ta-Token が無い。
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":    []string{(&http.Cookie{Name: cookieTaSess, Value: "session-da-yo", Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr: []string{"start new session"},
	}, nil)

	resp, err := cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
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

	resp, err = cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
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
	// util.SetupConsoleLog("github.com/realglobe-Inc", level.ALL)
	// defer util.SetupConsoleLog("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	// プロキシ先を用意。
	destPort, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	dest, err := util.NewTestHttpServer(destPort)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// テストするプロキシサーバーを用意。
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// 認証する。
	sessId := "session-da-yo"
	token := "token-da-yo"
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":      []string{(&http.Cookie{Name: cookieTaSess, Value: sessId, Expires: time.Now().Add(10 * time.Second)}).String()},
		headerAuthTaErr:   []string{"start new session"},
		headerAuthTaToken: []string{token},
	}, nil)
	dest.AddResponse(http.StatusOK, nil, []byte("body da yo"))

	resp, err := cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
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
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	errCh := make(chan error, 1)
	rPipe, wPipe := io.Pipe()
	go func() {
		defer wPipe.Close()
		buff := make([]byte, (1 << 21) /* 2 MB */)
		for n := 0; n < (1 << 35); /* 32 GB */ {
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
		for n := 0; n < (1 << 35); {
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
	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	sys := newTestSystem()
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
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
