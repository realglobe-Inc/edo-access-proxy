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
	"net/http"

	"github.com/realglobe-Inc/edo-lib/jwk"
	"github.com/realglobe-Inc/go-lib/erro"
)

const (
	test_logPath = "/tmp/edo-access-proxy.log"
	test_logSize = 100000000
	test_logNum  = 10
	test_logAddr = "127.0.0.1:24224"
	test_logTag  = "edo-access-proxy"
	test_socPort = 12345
	test_socPath = "/tmp/edo-access-proxy.sock"
)

var (
	test_key, _ = jwk.FromMap(map[string]interface{}{
		"kty": "RSA",
		"n":   "5cadP6Vvv6ABglXpSeXYxPB321gtSwmjccsHr2-YKmBm22KWF2A1b68LJ3mA8eG5NPSRL6macCMttxsoAKwaCxOxn-6dNOKXNLQ1S0WsE4yY2QLoi9Cj_sY8yfdk_wb0ZM5kyE99GjFFLDvnh-RjHIf2cbXPyPfbeLigeeon7jsxOw",
		"e":   "AQAB",
		"d":   "gOV1-Oo5UenUbuT6xXWmsHOlCOriHaH-iis22HdliQAjMxaO0_Yog8pSG4bRit7xIn-_olkmRZm2X21gd2AUC_mkE7Nytw5t_pioMzupEVVGApIFuc2_ryf5VPSznx3zk5FY6XCgUf6BnJ188WRUv3CnnNuAmEJtP6MhWmoKlPMpgQ",
		"p":   "9556qFgzilKEEhQ41fVzvLm5vKpiCc0IABG1CDQ_VTr4KGoOcqSHx6__yqYFQlzgizkG-zVxBQSs-6GZ3eA-t4s",
		"q":   "7Y2H2tRgIm9UjN0OlszOBcOXqPicE5KlseuNCIJZo1SyW30h-N2ssjCeiSDPrqm5QGZ637EAmhvNsPNOxzwLIxE",
		"dp":  "sa3EMdvoT87Z-ecMyWpw-_EA-AICiynWHcaW8iYbc9r2inlfmJ-61mzRzOXITFA8x2nKOqOkT4eFYKIauHzaQ_U",
		"dq":  "EhoQ2ioI0VbueHV34SHmKSZIbkXTjuJD4hTzAEz-i6Wuma4lYpNxz3pI-mYXrVWdmjy07ErOou-vcuZ3gFMg_iE",
		"qi":  "DbisQAteFbdCaNy6TyNy5UgZjdPba1bhKI3iIXalno_5HRrK4tUzu9VHdYVj5-iscIw5za9cPMLFr3zQvWa-gzA",
	})
)

func newTestRequest(uri, toTaUri string, body []byte) (*http.Request, error) {
	var meth string
	if len(body) > 0 {
		meth = "POST"
	} else {
		meth = "GET"
	}
	r, err := http.NewRequest(meth, uri, bytes.NewReader(body))
	if err != nil {
		return nil, erro.Wrap(err)
	}
	r.Header.Set("X-Edo-Access-Proxy-Uri", toTaUri)
	return r, nil
}
