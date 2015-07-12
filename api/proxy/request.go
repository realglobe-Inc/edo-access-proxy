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
	"net/url"

	"github.com/realglobe-Inc/go-lib/erro"
)

type request struct {
	toUri_ *url.URL
}

func parseRequest(r *http.Request) (*request, error) {
	toUriStr := r.Header.Get(tagX_edo_access_proxy_uri)
	if toUriStr == "" { // url.Parse は空文字列ではエラーにならない。
		return nil, erro.New("no destination uri")
	}
	r.Header.Del(tagX_edo_access_proxy_uri)
	toUri, err := url.Parse(toUriStr)
	if err != nil {
		return nil, erro.Wrap(err)
	}
	return &request{
		toUri,
	}, nil
}

func (req *request) toUri() *url.URL {
	return req.toUri_
}
