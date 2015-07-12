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
	"net/http"
	"time"

	"github.com/realglobe-Inc/go-lib/erro"
)

type response struct {
	sessId  string
	sessExp time.Time
	tok     string
}

func parseResponse(resp *http.Response, sessLabel string) (*response, error) {
	if resp.StatusCode != http.StatusUnauthorized {
		return nil, erro.New("invalid response code ", resp.StatusCode)
	}
	var sessId string
	var sessExp time.Time
	for _, cook := range resp.Cookies() {
		if cook.Name == sessLabel {
			sessId = cook.Value
			sessExp = cook.Expires
			if sessExp.IsZero() {
				sessExp = time.Now().Add(time.Duration(cook.MaxAge) * time.Second)
			}
			break
		}
	}
	if sessId == "" {
		return nil, erro.New("no session")
	}
	tok := resp.Header.Get(tagX_edo_auth_ta_token)
	if tok == "" {
		return nil, erro.New("no token")
	}
	return &response{
		sessId,
		sessExp,
		tok,
	}, nil
}

func (resp *response) sessionId() string {
	return resp.sessId
}

func (resp *response) sessionExpires() time.Time {
	return resp.sessExp
}

func (resp *response) token() string {
	return resp.tok
}
