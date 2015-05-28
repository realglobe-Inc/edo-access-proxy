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
	"github.com/realglobe-Inc/edo-lib/prand"
	"io"
	"io/ioutil"
	"testing"
	"time"
)

// メモリだけでテスト。
func TestBufferMemory(t *testing.T) {
	data := []byte(prand.New(time.Hour).Bytes(100))
	base := ioutil.NopCloser(bytes.NewReader(data))
	buff := newBuffer(base, len(data), test_pref)
	defer buff.dispose()

	for i := 0; i <= len(data); i++ {
		buff.rollback()
		data2 := make([]byte, i)
		if _, err := io.ReadFull(buff, data2); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(data2, data[:len(data2)]) {
			t.Error(i)
			t.Error(string(data2))
			t.Fatal(string(data[:len(data2)]))
		}
	}
}

func TestBuffer(t *testing.T) {
	data := []byte(prand.New(time.Hour).String(100))
	base := ioutil.NopCloser(bytes.NewReader(data))
	buff := newBuffer(base, len(data)/2, test_pref)
	defer buff.dispose()

	for i := 0; i <= len(data); i++ {
		buff.rollback()
		data2 := make([]byte, i)
		if _, err := io.ReadFull(buff, data2); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(data2, data[:len(data2)]) {
			t.Error(i)
			t.Error(string(data2))
			t.Fatal(string(data[:len(data2)]))
		}
	}
}
