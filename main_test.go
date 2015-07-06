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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/realglobe-Inc/edo-auth/database/token"
	idpdb "github.com/realglobe-Inc/edo-idp-selector/database/idp"
	tadb "github.com/realglobe-Inc/edo-idp-selector/database/ta"
	"github.com/realglobe-Inc/edo-lib/jwk"
	logutil "github.com/realglobe-Inc/edo-lib/log"
	"github.com/realglobe-Inc/edo-lib/strset/strsetutil"
	"github.com/realglobe-Inc/edo-lib/test"
	"github.com/realglobe-Inc/go-lib/erro"
	"github.com/realglobe-Inc/go-lib/rglog/level"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

func init() {
	logutil.SetupConsole(logRoot, level.OFF)
}

var monPool, _ = mgo.DialWithTimeout(test_monAddr, time.Minute)

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

// 正常系。
func TestServer(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole(logRoot, level.ALL)
	// defer logutil.SetupConsole(logRoot, level.OFF)
	// ////////////////////////////////

	if monPool == nil {
		t.SkipNow()
	}
	red, err := test.NewRedisServer()
	if err != nil {
		t.Fatal(err)
	} else if red == nil {
		t.SkipNow()
	}

	// ID プロバイダの準備。
	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()

	// 連携先 TA の準備。
	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()

	// 環境設定。
	param, err := newTestParameter()
	if err != nil {
		t.Fatal(err)
	}
	param.socPort, err = test.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	// 鍵の準備。
	keyDbPath, err := setupKeyDb(param.keyDbPath, []jwk.Key{test_key})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(keyDbPath)
	param.keyDbPath = keyDbPath
	// ID プロバイダ DB の準備。
	param.idpDbTag = param.idpDbTag + strconv.FormatInt(time.Now().UnixNano(), 16)
	if err := setupIdpDb(param.idpDbTag, param.idpDbTag2, []idpdb.Element{idp}); err != nil {
		t.Fatal(err)
	}
	defer clearIdpDb(param.idpDbTag, param.idpDbTag2)
	// アクセストークン DB の準備。
	if err := token.NewRedisDb(red.Pool(), param.tokDbTag).Save(token.New(test_tokId, test_tokTag, time.Now().Add(time.Minute), idp.Id(), strsetutil.New("openid")), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	defer red.Close()
	param.tokDbAddr = red.Address()

	testServer(t, param, idpServ, toTaServ)
}

// データベースをちゃんと使った正常系。
func TestServerWithDb(t *testing.T) {
	// ////////////////////////////////
	// logutil.SetupConsole(logRoot, level.ALL)
	// defer logutil.SetupConsole(logRoot, level.OFF)
	// ////////////////////////////////

	if monPool == nil {
		t.SkipNow()
	}
	red, err := test.NewRedisServer()
	if err != nil {
		t.Fatal(err)
	} else if red == nil {
		t.SkipNow()
	}

	// ID プロバイダの準備。
	idpServ, err := newTestIdProvider([]jwk.Key{test_idpKey})
	if err != nil {
		t.Fatal(err)
	}
	defer idpServ.close()
	idp := idpServ.info()

	// 連携先 TA の準備。
	toTaServ, err := newTestTa()
	if err != nil {
		t.Fatal(err)
	}
	defer toTaServ.close()

	// 環境設定。
	param, err := newTestParameter()
	if err != nil {
		t.Fatal(err)
	}
	// 鍵の準備。
	param.keyDbType = "redis"
	param.keyDbAddr = red.Address()
	keyDbPath, err := setupKeyDb(param.keyDbPath, []jwk.Key{test_key})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(keyDbPath)
	param.keyDbPath = keyDbPath
	// web DB の準備。
	param.webDbType = "redis"
	param.webDbAddr = red.Address()
	// ID プロバイダ DB の準備。
	param.idpDbTag = param.idpDbTag + strconv.FormatInt(time.Now().UnixNano(), 16)
	if err := setupIdpDb(param.idpDbTag, param.idpDbTag2, []idpdb.Element{idp}); err != nil {
		t.Fatal(err)
	}
	defer clearIdpDb(param.idpDbTag, param.idpDbTag2)
	// アクセストークン DB の準備。
	if err := token.NewRedisDb(red.Pool(), param.tokDbTag).Save(token.New(test_tokId, test_tokTag, time.Now().Add(time.Minute), idp.Id(), strsetutil.New("openid")), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	defer red.Close()
	param.tokDbAddr = red.Address()
	// セッション DB の準備。
	param.sessDbType = "redis"
	param.sessDbAddr = red.Address()

	testServer(t, param, idpServ, toTaServ)
}

func testServer(t *testing.T, param *parameters, idpServ *testIdProvider, toTaServ *testTa) {
	idp := idpServ.info()
	toTa := toTaServ.info()

	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(param)
	}()
	defer func() { param.shutCh <- struct{}{} }()

	selfUri := "http://localhost:" + strconv.Itoa(param.socPort)
	exp := time.Now().Add(time.Minute)
	for {
		if time.Now().After(exp) {
			t.Fatal("timeout")
		}
		r, err := http.NewRequest("GET", selfUri+param.pathOk, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Connection", "close")
		if _, err := (&http.Client{}).Do(r); err == nil {
			break
		}

		select {
		case err := <-errCh:
			t.Fatal(err)
		default:
		}
		time.Sleep(time.Millisecond)
	}

	{
		s, h, b, err := newTestIdpResponse(param, idp, toTa.Id())
		if err != nil {
			t.Fatal(err)
		}
		idpServ.addResponse(s, h, b)
	}

	stat, head, body, err := newTestToTaResponse()
	if err != nil {
		t.Fatal(err)
	}
	toTaServ.addResponse(stat, head, body)

	reqBody := []byte("request,requester,requestest")
	r, err := newTestRequest(selfUri+param.pathProx, idp.Id(), toTa.Id(), reqBody)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "close")
	resp, err := (&http.Client{}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != stat {
		t.Error(resp.StatusCode)
		t.Fatal(stat)
	}
	for k, vs := range head {
		if h := resp.Header.Get(k); h != vs[0] {
			t.Error(h)
			t.Fatal(vs[0])
		}
	}
	if buff, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(buff, body) {
		t.Error(string(buff))
		t.Fatal(string(body))
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

func setupIdpDb(db, coll string, idps []idpdb.Element) error {
	conn := monPool.New()
	defer conn.Close()

	for _, idp := range idps {
		keys := []map[string]interface{}{}
		for _, key := range idp.Keys() {
			keys = append(keys, key.ToMap())
		}
		m := bson.M{
			"issuer":                    idp.Id(),
			"authorization_endpoint":    idp.AuthUri(),
			"token_endpoint":            idp.TokenUri(),
			"userinfo_endpoint":         idp.AccountUri(),
			"cooperation_from_endpoint": idp.CoopFromUri(),
			"cooperation_to_endpoint":   idp.CoopToUri(),
			"jwks": keys,
		}
		for k, v := range idp.Names() {
			if k == "" {
				m["issuer_name"] = v
			} else {
				m["issuer_name#"+k] = v
			}
		}
		if err := conn.DB(db).C(coll).Insert(m); err != nil {
			return erro.Wrap(err)
		}
	}
	return nil
}

func clearIdpDb(db, coll string) error {
	conn := monPool.New()
	defer conn.Close()

	return conn.DB(db).DropDatabase()
}
