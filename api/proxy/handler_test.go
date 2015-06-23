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
	tadb "github.com/realglobe-Inc/edo-idp-selector/database/ta"
	"github.com/realglobe-Inc/edo-lib/jwk"
	"github.com/realglobe-Inc/edo-lib/jwt"
	logutil "github.com/realglobe-Inc/edo-lib/log"
	"github.com/realglobe-Inc/edo-lib/rand"
	"github.com/realglobe-Inc/edo-lib/server"
	"github.com/realglobe-Inc/edo-lib/strset"
	"github.com/realglobe-Inc/edo-lib/strset/strsetutil"
	"github.com/realglobe-Inc/edo-lib/test"
	"github.com/realglobe-Inc/go-lib/erro"
	"github.com/realglobe-Inc/go-lib/rglog/level"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func init() {
	logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
}

func newTestHandler(keys []jwk.Key, idps []idpdb.Element) *handler {
	return New(
		server.NewStopper(),
		"https://from.example.org",
		test_frTaSigAlg,
		"",
		"SHA256",
		"Edo-Cooperation",
		time.Hour,
		20,
		time.Minute,
		1024,
		keydb.NewMemoryDb(keys),
		idpdb.NewMemoryDb(idps),
		token.NewMemoryDb(),
		session.NewMemoryDb(),
		rand.New(time.Minute),
		nil,
		true,
	).(*handler)
}

type testIdProvider struct {
	base *test.HttpServer
	keys []jwk.Key
}

func newTestIdProvider(keys []jwk.Key) (*testIdProvider, error) {
	base, err := test.NewHttpServer(time.Minute)
	if err != nil {
		return nil, erro.Wrap(err)
	}
	return &testIdProvider{base, keys}, nil
}

func (this *testIdProvider) close() {
	this.base.Close()
}

func (this *testIdProvider) info() idpdb.Element {
	return idpdb.New(
		this.base.URL,
		nil,
		this.base.URL+"/auth",
		this.base.URL+"/token",
		this.base.URL+"/userinfo",
		this.base.URL+"/coop/from",
		this.base.URL+"/coop/to",
		this.keys,
	)
}

func (this *testIdProvider) selfId() string {
	return this.base.URL
}

func (this *testIdProvider) addResponse(status int, header http.Header, body []byte) <-chan *http.Request {
	return this.base.AddResponse(status, header, body)
}

type testTa struct {
	base *test.HttpServer
}

func newTestTa() (*testTa, error) {
	base, err := test.NewHttpServer(time.Minute)
	if err != nil {
		return nil, erro.Wrap(err)
	}
	return &testTa{base}, nil
}

func (this *testTa) close() {
	this.base.Close()
}

func (this *testTa) info() tadb.Element {
	return tadb.New(
		this.base.URL,
		nil,
		strsetutil.New(this.base.URL+"/callback"),
		nil,
		false,
		"",
	)
}

func (this *testTa) addResponse(status int, header http.Header, body []byte) <-chan *http.Request {
	return this.base.AddResponse(status, header, body)
}

// 関係する ID プロバイダが 1 つの場合の正常系。
// 転送リクエストから X-Access-Proxy-Users, X-Access-Proxy-To, X-Access-Proxy-To-Id ヘッダを取り除くことの検査。
// 転送レスポンスをそのまま返すことの検査。
func TestSingleNormal(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()

	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()
	toTa := toTaServ.info()

	hndl := newTestHandler([]jwk.Key{test_frTaKey}, []idpdb.Element{idp})

	now := time.Now()
	hndl.tokDb.Save(token.New(test_tok, test_tokTag, now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))

	reqBody := []byte("request,requester,requestest")
	r, err := newTestSingleRequest(idp.Id(), toTa.Id(), reqBody)
	if err != nil {
		t.Fatal(err)
	}

	var idpReqCh <-chan *http.Request
	{
		s, h, b, err := newTestSingleIdpResponse(hndl, idp, toTa.Id())
		if err != nil {
			t.Fatal(err)
		}
		idpReqCh = idpServ.addResponse(s, h, b)
	}

	stat, head, body, err := newTestToTaResponse()
	if err != nil {
		t.Fatal(err)
	}
	toTaReqCh := toTaServ.addResponse(stat, head, body)

	w := httptest.NewRecorder()
	hndl.ServeHTTP(w, r)

	select {
	case req := <-idpReqCh:
		if contType, contType2 := "application/json", req.Header.Get("Content-Type"); contType2 != contType {
			t.Error(contType)
			t.Fatal(contType2)
		}
		var buff struct {
			Response_type string
			From_client   string
			To_client     string
			Grant_type    string
			Access_token  string
			User_tag      string
			Users         map[string]string
		}
		if err := json.NewDecoder(req.Body).Decode(&buff); err != nil {
			t.Fatal(err)
		} else if respType := "code_token"; buff.Response_type != respType {
			t.Error(buff.Response_type)
			t.Fatal(respType)
		} else if buff.From_client != hndl.selfId {
			t.Error(buff.From_client)
			t.Fatal(hndl.selfId)
		} else if buff.To_client != toTa.Id() {
			t.Error(buff.To_client)
			t.Fatal(toTa.Id())
		} else if grntType := "access_token"; buff.Grant_type != grntType {
			t.Error(buff.Grant_type)
			t.Fatal(grntType)
		} else if buff.Access_token != test_tok {
			t.Error(buff.Access_token)
			t.Fatal(test_tok)
		} else if buff.User_tag != test_acntTag {
			t.Error(buff.User_tag)
			t.Fatal(test_acntTag)
		} else if acnts := map[string]string{test_subAcnt1Tag: test_subAcnt1Id}; !reflect.DeepEqual(buff.Users, acnts) {
			t.Error(buff.Users)
			t.Fatal(acnts)
		}
	case <-time.After(time.Minute):
		t.Fatal("no request")
	}

	select {
	case req := <-toTaReqCh:
		if req.Method != r.Method {
			t.Error(req.Method)
			t.Fatal(r.Method)
		} else if head := req.Header.Get("X-Access-Proxy-Users"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if head := req.Header.Get("X-Access-Proxy-To"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if head := req.Header.Get("X-Access-Proxy-To-Id"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if buff, err := ioutil.ReadAll(req.Body); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(buff, reqBody) {
			t.Error(string(buff))
			t.Fatal(string(reqBody))
		}
	case <-time.After(time.Minute):
		t.Fatal("no request")
	}

	if w.Code != stat {
		t.Error(w.Code)
		t.Fatal(stat)
	}
	for k, vs := range head {
		if h := w.HeaderMap.Get(k); h != vs[0] {
			t.Error(h)
			t.Fatal(vs[0])
		}
	}
	if buff, err := ioutil.ReadAll(w.Body); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(buff, body) {
		t.Error(string(buff))
		t.Fatal(string(body))
	}
}

// X-Access-Proxy-Users ヘッダが無ければ拒否することの検査。
func TestDenyNoUsers(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	testDenyNoSomething(t, "X-Access-Proxy-Users")
}

// X-Access-Proxy-To ヘッダが無ければ拒否することの検査。
func TestDenyNoTo(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	testDenyNoSomething(t, "X-Access-Proxy-To")
}

func testDenyNoSomething(t *testing.T, something string) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()

	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()
	toTa := toTaServ.info()

	hndl := newTestHandler([]jwk.Key{test_frTaKey}, []idpdb.Element{idp})

	now := time.Now()
	hndl.tokDb.Save(token.New(test_tok, test_tokTag, now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))

	r, err := newTestSingleRequest(idp.Id(), toTa.Id(), []byte("request,requester,requestest"))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Del(something)

	w := httptest.NewRecorder()
	hndl.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Error(w.Code)
		t.Fatal(http.StatusBadRequest)
	} else if w.HeaderMap.Get("X-Access-Proxy-Error") == "" {
		t.Fatal("no X-Access-Proxy-Error header")
	}
	var buff struct{ Error string }
	if err := json.NewDecoder(w.Body).Decode(&buff); err != nil {
		t.Fatal(err)
	} else if err := "invalid_request"; buff.Error != err {
		t.Error(buff.Error)
		t.Fatal(err)
	}
}

// 主体が指定されていなかったら拒否できることの検査。
func TestDenyNoMainAccount(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()

	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()
	toTa := toTaServ.info()

	hndl := newTestHandler([]jwk.Key{test_frTaKey}, []idpdb.Element{idp})

	now := time.Now()
	hndl.tokDb.Save(token.New(test_tok, test_tokTag, now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))
	hndl.tokDb.Save(token.New(test_tok+"a", test_tokTag+"a", now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))

	r, err := newTestSingleRequest(idp.Id(), toTa.Id(), []byte("request,requester,requestest"))
	if err != nil {
		t.Fatal(err)
	}
	{
		acnts := jwt.New()
		acnts.SetHeader("alg", "none")
		acnts.SetClaim(test_acntTag, map[string]interface{}{
			"iss": idp.Id(),
			"sub": test_acntId,
		})
		acnts.SetClaim(test_subAcnt1Tag, map[string]interface{}{
			"iss": idp.Id(),
			"sub": test_subAcnt1Id,
		})
		acntsBuff, err := acnts.Encode()
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Access-Proxy-Users", string(acntsBuff))
	}

	w := httptest.NewRecorder()
	hndl.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Error(w.Code)
		t.Fatal(http.StatusBadRequest)
	} else if w.HeaderMap.Get("X-Access-Proxy-Error") == "" {
		t.Fatal("no X-Access-Proxy-Error header")
	}
	var buff struct{ Error string }
	if err := json.NewDecoder(w.Body).Decode(&buff); err != nil {
		t.Fatal(err)
	} else if err := "invalid_request"; buff.Error != err {
		t.Error(buff.Error)
		t.Fatal(err)
	}
}

// 複数の主体が指定されていたら拒否できることの検査。
func TestDenyTwoMainAccount(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()

	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()
	toTa := toTaServ.info()

	hndl := newTestHandler([]jwk.Key{test_frTaKey}, []idpdb.Element{idp})

	now := time.Now()
	hndl.tokDb.Save(token.New(test_tok, test_tokTag, now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))
	hndl.tokDb.Save(token.New(test_tok+"a", test_tokTag+"a", now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))

	r, err := newTestSingleRequest(idp.Id(), toTa.Id(), []byte("request,requester,requestest"))
	if err != nil {
		t.Fatal(err)
	}
	{
		acnts := jwt.New()
		acnts.SetHeader("alg", "none")
		acnts.SetClaim(test_acntTag, map[string]interface{}{"at_tag": test_tokTag})
		acnts.SetClaim(test_subAcnt1Tag, map[string]interface{}{"at_tag": test_tokTag + "a"})
		acntsBuff, err := acnts.Encode()
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Access-Proxy-Users", string(acntsBuff))
	}

	w := httptest.NewRecorder()
	hndl.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Error(w.Code)
		t.Fatal(http.StatusBadRequest)
	} else if w.HeaderMap.Get("X-Access-Proxy-Error") == "" {
		t.Fatal("no X-Access-Proxy-Error header")
	}
	var buff struct{ Error string }
	if err := json.NewDecoder(w.Body).Decode(&buff); err != nil {
		t.Fatal(err)
	} else if err := "invalid_request"; buff.Error != err {
		t.Error(buff.Error)
		t.Fatal(err)
	}
}

// ID プロバイダから拒否されたら拒否できることの検査。
func TestDenyIfDenied(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()

	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()
	toTa := toTaServ.info()

	hndl := newTestHandler([]jwk.Key{test_frTaKey}, []idpdb.Element{idp})

	now := time.Now()
	hndl.tokDb.Save(token.New(test_tok, test_tokTag, now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))

	r, err := newTestSingleRequest(idp.Id(), toTa.Id(), []byte("request,requester,requestest"))
	if err != nil {
		t.Fatal(err)
	}

	idpServ.addResponse(http.StatusForbidden, http.Header{"Content-Type": {"application/json"}}, []byte(`{"error":"access_denied"}`))

	w := httptest.NewRecorder()
	hndl.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Error(w.Code)
		t.Fatal(http.StatusBadRequest)
	} else if w.HeaderMap.Get("X-Access-Proxy-Error") == "" {
		t.Fatal("no X-Access-Proxy-Error header")
	}
	var buff struct{ Error string }
	if err := json.NewDecoder(w.Body).Decode(&buff); err != nil {
		t.Fatal(err)
	} else if err := "server_error"; buff.Error != err {
		t.Error(buff.Error)
		t.Fatal(err)
	}
}

// セッションを使う場合の正常系。
func TestSession(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()

	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()
	toTa := toTaServ.info()

	hndl := newTestHandler([]jwk.Key{test_frTaKey}, []idpdb.Element{idp})

	now := time.Now()
	hndl.tokDb.Save(token.New(test_tok, test_tokTag, now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))
	hndl.sessDb.Save(session.New(test_sessId, now.Add(time.Minute), toTa.Id(), map[string]*session.Account{
		test_acntTag: session.NewMainAccount(test_tokTag),
	}), now.Add(time.Minute))

	reqBody := []byte("request,requester,requestest")
	r, err := newTestSessionRequest(idp.Id(), toTa.Id(), reqBody)
	if err != nil {
		t.Fatal(err)
	}

	stat, head, body, err := newTestToTaResponse()
	if err != nil {
		t.Fatal(err)
	}
	toTaReqCh := toTaServ.addResponse(stat, head, body)

	w := httptest.NewRecorder()
	hndl.ServeHTTP(w, r)

	select {
	case req := <-toTaReqCh:
		if req.Method != r.Method {
			t.Error(req.Method)
			t.Fatal(r.Method)
		} else if head := req.Header.Get("X-Access-Proxy-Users"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if head := req.Header.Get("X-Access-Proxy-To"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if head := req.Header.Get("X-Access-Proxy-To-Id"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if cook, err := req.Cookie("Edo-Cooperation"); err != nil {
			t.Fatal(err)
		} else if cook.Value != test_sessId {
			t.Error(cook.Value)
			t.Fatal(test_sessId)
		} else if buff, err := ioutil.ReadAll(req.Body); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(buff, reqBody) {
			t.Error(string(buff))
			t.Fatal(string(reqBody))
		}
	case <-time.After(time.Minute):
		t.Fatal("no request")
	}

	if w.Code != stat {
		t.Error(w.Code)
		t.Fatal(stat)
	}
	for k, vs := range head {
		if h := w.HeaderMap.Get(k); h != vs[0] {
			t.Error(h)
			t.Fatal(vs[0])
		}
	}
	if buff, err := ioutil.ReadAll(w.Body); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(buff, body) {
		t.Error(string(buff))
		t.Fatal(string(body))
	}
}

// セッションを使ったけど拒否されたので、ID プロバイダ経由でやり直す正常系。
func TestRetry(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()

	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()
	toTa := toTaServ.info()

	hndl := newTestHandler([]jwk.Key{test_frTaKey}, []idpdb.Element{idp})

	now := time.Now()
	hndl.tokDb.Save(token.New(test_tok, test_tokTag, now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))
	hndl.sessDb.Save(session.New(test_sessId, now.Add(time.Minute), toTa.Id(), map[string]*session.Account{
		test_acntTag: session.NewMainAccount(test_tokTag),
	}), now.Add(time.Minute))

	reqBody := []byte("request,requester,requestest")
	r, err := newTestSessionRequest(idp.Id(), toTa.Id(), reqBody)
	if err != nil {
		t.Fatal(err)
	}

	toTaServ.addResponse(http.StatusForbidden,
		http.Header{"Content-Type": {"application/json"}, "X-Edo-Cooperation-Error": {"session expired"}},
		[]byte(`{"error":"access_denied"}`))

	var idpReqCh <-chan *http.Request
	{
		s, h, b, err := newTestIdpResponse(hndl, idp, toTa.Id())
		if err != nil {
			t.Fatal(err)
		}
		idpReqCh = idpServ.addResponse(s, h, b)
	}

	stat, head, body, err := newTestToTaResponse()
	if err != nil {
		t.Fatal(err)
	}
	toTaReqCh := toTaServ.addResponse(stat, head, body)

	w := httptest.NewRecorder()
	hndl.ServeHTTP(w, r)

	select {
	case req := <-idpReqCh:
		if contType, contType2 := "application/json", req.Header.Get("Content-Type"); contType2 != contType {
			t.Error(contType)
			t.Fatal(contType2)
		}
		var buff struct {
			Response_type string
			From_client   string
			To_client     string
			Grant_type    string
			Access_token  string
			User_tag      string
			Users         map[string]string
		}
		if err := json.NewDecoder(req.Body).Decode(&buff); err != nil {
			t.Fatal(err)
		} else if respType := "code_token"; buff.Response_type != respType {
			t.Error(buff.Response_type)
			t.Fatal(respType)
		} else if buff.From_client != hndl.selfId {
			t.Error(buff.From_client)
			t.Fatal(hndl.selfId)
		} else if buff.To_client != toTa.Id() {
			t.Error(buff.To_client)
			t.Fatal(toTa.Id())
		} else if grntType := "access_token"; buff.Grant_type != grntType {
			t.Error(buff.Grant_type)
			t.Fatal(grntType)
		} else if buff.Access_token != test_tok {
			t.Error(buff.Access_token)
			t.Fatal(test_tok)
		} else if buff.User_tag != test_acntTag {
			t.Error(buff.User_tag)
			t.Fatal(test_acntTag)
		} else if len(buff.Users) > 0 {
			t.Fatal("accounts is exist")
		}
	case <-time.After(time.Minute):
		t.Fatal("no request")
	}

	select {
	case req := <-toTaReqCh:
		if req.Method != r.Method {
			t.Error(req.Method)
			t.Fatal(r.Method)
		} else if head := req.Header.Get("X-Access-Proxy-Users"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if head := req.Header.Get("X-Access-Proxy-To"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if head := req.Header.Get("X-Access-Proxy-To-Id"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if buff, err := ioutil.ReadAll(req.Body); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(buff, reqBody) {
			t.Error(string(buff))
			t.Fatal(string(reqBody))
		}
	case <-time.After(time.Minute):
		t.Fatal("no request")
	}

	if w.Code != stat {
		t.Error(w.Code)
		t.Fatal(stat)
	}
	for k, vs := range head {
		if h := w.HeaderMap.Get(k); h != vs[0] {
			t.Error(h)
			t.Fatal(vs[0])
		}
	}
	if buff, err := ioutil.ReadAll(w.Body); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(buff, body) {
		t.Error(string(buff))
		t.Fatal(string(body))
	}
}

// プロキシ先がおかしかったら拒否できることの検査。
func TestDenyInvalidTo(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()

	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()
	toTa := toTaServ.info()

	hndl := newTestHandler([]jwk.Key{test_frTaKey}, []idpdb.Element{idp})

	now := time.Now()
	hndl.tokDb.Save(token.New(test_tok, test_tokTag, now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))

	r, err := newTestSingleRequest(idp.Id(), toTa.Id(), []byte("request,requester,requestest"))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Access-Proxy-To", toTa.Id()+"a"+test_path)

	{
		s, h, b, err := newTestSingleIdpResponse(hndl, idp, toTa.Id())
		if err != nil {
			t.Fatal(err)
		}
		idpServ.addResponse(s, h, b)
	}

	w := httptest.NewRecorder()
	hndl.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Error(w.Code)
		t.Fatal(http.StatusNotFound)
	} else if w.HeaderMap.Get("X-Access-Proxy-Error") == "" {
		t.Fatal("no X-Access-Proxy-Error header")
	}
	var buff struct{ Error string }
	if err := json.NewDecoder(w.Body).Decode(&buff); err != nil {
		t.Fatal(err)
	} else if err := "invalid_request"; buff.Error != err {
		t.Error(buff.Error)
		t.Fatal(err)
	}
}

// 関係する ID プロバイダが 2 つ以上の場合の正常系。
// 転送リクエストから X-Access-Proxy-Users, X-Access-Proxy-To, X-Access-Proxy-To-Id ヘッダを取り除くことの検査。
// 転送レスポンスをそのまま返すことの検査。
func TestMultiNormal(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole("github.com/realglobe-Inc", level.ALL)
	// defer logutil.SetupConsole("github.com/realglobe-Inc", level.OFF)
	// ////////////////////////////////

	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()
	subIdpServ, err := newTestIdProvider([]jwk.Key{test_subIdpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer subIdpServ.close()
	subIdp := subIdpServ.info()

	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()
	toTa := toTaServ.info()

	hndl := newTestHandler([]jwk.Key{test_frTaKey}, []idpdb.Element{idp, subIdp})

	now := time.Now()
	hndl.tokDb.Save(token.New(test_tok, test_tokTag, now.Add(time.Minute), idp.Id(), test_scop), now.Add(time.Minute))

	reqBody := []byte("request,requester,requestest")
	r, err := newTestMultiRequest(idp.Id(), subIdp.Id(), toTa.Id(), reqBody)
	if err != nil {
		t.Fatal(err)
	}

	subAcnt2HVal := calcTestSubAccount2HashValue(subIdp.Id())
	var codTok, ref []byte
	var idpReqCh <-chan *http.Request
	{
		s, h, b, codTok2, ref2, err := newTestMainIdpResponse(hndl, idp, subIdp.Id(), toTa.Id(), subAcnt2HVal)
		if err != nil {
			t.Fatal(err)
		}
		codTok, ref = codTok2, ref2
		idpReqCh = idpServ.addResponse(s, h, b)
	}
	var subCodTok []byte
	var subIdpReqCh <-chan *http.Request
	{
		s, h, b, codTok2, err := newTestSubIdpResponse(hndl, subIdp, toTa.Id(), ref)
		if err != nil {
			t.Fatal(err)
		}
		subCodTok = codTok2
		subIdpReqCh = subIdpServ.addResponse(s, h, b)
	}

	stat, head, body, err := newTestToTaResponse()
	if err != nil {
		t.Fatal(err)
	}
	toTaReqCh := toTaServ.addResponse(stat, head, body)

	w := httptest.NewRecorder()
	hndl.ServeHTTP(w, r)

	select {
	case req := <-idpReqCh:
		if contType, contType2 := "application/json", req.Header.Get("Content-Type"); contType2 != contType {
			t.Error(contType)
			t.Fatal(contType2)
		}
		var buff struct {
			Response_type   string
			From_client     string
			To_client       string
			Grant_type      string
			Access_token    string
			User_tag        string
			Users           map[string]string
			Related_users   map[string]string
			Hash_alg        string
			Related_issuers strset.Set
		}
		if err := json.NewDecoder(req.Body).Decode(&buff); err != nil {
			t.Fatal(err)
		} else if respType := "code_token referral"; buff.Response_type != respType {
			t.Error(buff.Response_type)
			t.Fatal(respType)
		} else if buff.From_client != hndl.selfId {
			t.Error(buff.From_client)
			t.Fatal(hndl.selfId)
		} else if buff.To_client != toTa.Id() {
			t.Error(buff.To_client)
			t.Fatal(toTa.Id())
		} else if grntType := "access_token"; buff.Grant_type != grntType {
			t.Error(buff.Grant_type)
			t.Fatal(grntType)
		} else if buff.Access_token != test_tok {
			t.Error(buff.Access_token)
			t.Fatal(test_tok)
		} else if buff.User_tag != test_acntTag {
			t.Error(buff.User_tag)
			t.Fatal(test_acntTag)
		} else if acnts := map[string]string{test_subAcnt1Tag: test_subAcnt1Id}; !reflect.DeepEqual(buff.Users, acnts) {
			t.Error(buff.Users)
			t.Fatal(acnts)
		} else if relAcnts := map[string]string{test_subAcnt2Tag: subAcnt2HVal}; !reflect.DeepEqual(buff.Related_users, relAcnts) {
			t.Error(buff.Related_users)
			t.Fatal(relAcnts)
		} else if buff.Hash_alg != test_hAlg {
			t.Error(buff.Hash_alg)
			t.Fatal(test_hAlg)
		} else if relIdps := strsetutil.New(subIdp.Id()); !reflect.DeepEqual(map[string]bool(buff.Related_issuers), relIdps) {
			t.Error(buff.Related_issuers)
			t.Fatal(relIdps)
		}
	case <-time.After(time.Minute):
		t.Fatal("no request")
	}
	select {
	case req := <-subIdpReqCh:
		if contType, contType2 := "application/json", req.Header.Get("Content-Type"); contType2 != contType {
			t.Error(contType)
			t.Fatal(contType2)
		}
		var buff struct {
			Response_type string
			Grant_type    string
			Referral      string
			Users         map[string]string
		}
		if err := json.NewDecoder(req.Body).Decode(&buff); err != nil {
			t.Fatal(err)
		} else if respType := "code_token"; buff.Response_type != respType {
			t.Error(buff.Response_type)
			t.Fatal(respType)
		} else if grntType := "referral"; buff.Grant_type != grntType {
			t.Error(buff.Grant_type)
			t.Fatal(grntType)
		} else if buff.Referral != string(ref) {
			t.Error(buff.Referral)
			t.Fatal(string(ref))
		} else if acnts := map[string]string{test_subAcnt2Tag: test_subAcnt2Id}; !reflect.DeepEqual(buff.Users, acnts) {
			t.Error(buff.Users)
			t.Fatal(acnts)
		}
	case <-time.After(time.Minute):
		t.Fatal("no request")
	}

	select {
	case req := <-toTaReqCh:
		if req.Method != r.Method {
			t.Error(req.Method)
			t.Fatal(r.Method)
		} else if head := req.Header.Get("X-Access-Proxy-Users"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if head := req.Header.Get("X-Access-Proxy-To"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if head := req.Header.Get("X-Access-Proxy-To-Id"); head != "" {
			t.Error("header is exist")
			t.Fatal(head)
		} else if codToks, codToks2 := strsetutil.New(string(codTok), string(subCodTok)), strsetutil.New(req.Header["X-Edo-Code-Tokens"]...); !reflect.DeepEqual(codToks2, codToks) {
			t.Error(codToks2)
			t.Fatal(codToks)
		} else if buff, err := ioutil.ReadAll(req.Body); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(buff, reqBody) {
			t.Error(string(buff))
			t.Fatal(string(reqBody))
		}
	case <-time.After(time.Minute):
		t.Fatal("no request")
	}

	if w.Code != stat {
		t.Error(w.Code)
		t.Fatal(stat)
	}
	for k, vs := range head {
		if h := w.HeaderMap.Get(k); h != vs[0] {
			t.Error(h)
			t.Fatal(vs[0])
		}
	}
	if buff, err := ioutil.ReadAll(w.Body); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(buff, body) {
		t.Error(string(buff))
		t.Fatal(string(body))
	}
}
