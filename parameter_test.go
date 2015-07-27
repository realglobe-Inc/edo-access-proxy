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
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	logutil "github.com/realglobe-Inc/edo-lib/log"
	"github.com/realglobe-Inc/edo-lib/server"
	"github.com/realglobe-Inc/go-lib/erro"
)

func newTestParameter() (*parameters, error) {
	file, err := ioutil.TempFile("", "edo-access-proxy")
	if err != nil {
		return nil, erro.Wrap(err)
	}
	defer os.Remove(file.Name())

	if _, err := file.Write([]byte(`
-consLv=OFF
-logType=
-logLv=OFF
-logPath=` + test_logPath + `
-logSize=` + strconv.Itoa(test_logSize) + `
-logNum=` + strconv.Itoa(test_logNum) + `
-logAddr=` + test_logAddr + `
-logTag=` + test_logTag + `
-socType=tcp
-socPath=` + test_socPath + `
-socPort=` + strconv.Itoa(test_socPort) + `
-protType=http
-selfId=http://localhost:` + strconv.Itoa(test_socPort) + `
-sigAlg=ES384
-sigKid=
-hashAlg=SHA256
-pathOk=/ok
-pathProx=/proxy
-sessLabel=Edo-Cooperation
-sessDbExpIn=336h
-jtiLen=20
-jtiExpIn=1h
-fileThres=8192
-fileMax=100000
-redTimeout=30s
-redPoolSize=16
-redPoolExpIn=1m
-monTimeout=30s
-keyDbType=file
-keyDbPath=/tmp/edo-access-proxy.key
-keyDbAddr=localhost:6379
-keyDbTag=key
-keyDbExpIn=5m
-webDbType=direct
-webDbAddr=localhost:6379
-webDbTag=web
-webDbExpIn=168h
-idpDbType=mongo
-idpDbAddr=` + test_monAddr + `
-idpDbTag=edo-test
-idpDbTag2=idp
-tokDbType=redis
-tokDbAddr=localhost:6379
-tokDbTag=token
-sessDbType=memory
-sessDbAddr=localhost:6379
-sessDbTag=session
-noVeri
-debug
`)); err != nil {
		return nil, erro.Wrap(err)
	} else if err := file.Close(); err != nil {
		return nil, erro.Wrap(err)
	}

	param, err := parseParameters("edo-access-proxy", "-c", file.Name())
	if err != nil {
		return nil, erro.Wrap(err)
	}
	param.shutCh = make(chan struct{}, 5)
	return param, nil
}

func TestParameter(t *testing.T) {
	param, err := newTestParameter()
	if err != nil {
		t.Fatal(err)
	}

	if p := logutil.FileParameter(param); p == nil {
		t.Fatal("not file log parameter")
	} else if p.LogFilePath() != test_logPath {
		t.Error(p.LogFilePath())
		t.Fatal(test_logPath)
	} else if p.LogFileLimit() != test_logSize {
		t.Error(p.LogFileLimit())
		t.Fatal(test_logSize)
	} else if p.LogFileNumber() != test_logNum {
		t.Error(p.LogFileNumber())
		t.Fatal(test_logNum)
	} else if p := logutil.FluentdParameter(param); p == nil {
		t.Fatal("not fluentd log parameter")
	} else if p.LogFluentdAddress() != test_logAddr {
		t.Error(p.LogFluentdAddress())
		t.Fatal(test_logAddr)
	} else if p.LogFluentdTag() != test_logTag {
		t.Error(p.LogFluentdTag())
		t.Fatal(test_logTag)
	} else if p := server.TcpParameter(param); p == nil {
		t.Fatal("not tcp server parameter")
	} else if p.SocketPort() != test_socPort {
		t.Error(p.SocketPort())
		t.Fatal(test_socPort)
	} else if p := server.UnixParameter(param); p == nil {
		t.Fatal("not unix server parameter")
	} else if p.SocketPath() != test_socPath {
		t.Error(p.SocketPath())
		t.Fatal(test_socPath)
	} else if p := server.DebugParameter(param); p == nil {
		t.Fatal("not debug server parameter")
	} else if p.ShutdownChannel() == nil {
		t.Fatal("no shutdown channel")
	}
}
