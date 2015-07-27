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

package session

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/realglobe-Inc/go-lib/erro"
)

// メモリ上のセッションの格納庫。
type memoryDb struct {
	lock        sync.Mutex
	paramToElem map[string]*Element
	paramToExp  map[string]time.Time
}

func NewMemoryDb() Db {
	return &memoryDb{
		paramToElem: map[string]*Element{},
		paramToExp:  map[string]time.Time{},
	}
}

func (this *memoryDb) GetByParams(toTa string, acnts map[string]*Account) (*Element, error) {
	this.lock.Lock()
	defer this.lock.Unlock()

	// json.Marshal が非明示的に要素をソートすることに依存している。
	raw, err := json.Marshal(acnts)
	if err != nil {
		return nil, erro.Wrap(err)
	}

	key := toTa + string(raw)
	elem := this.paramToElem[key]
	if elem == nil {
		return nil, nil
	} else if time.Now().After(this.paramToExp[key]) {
		delete(this.paramToElem, key)
		delete(this.paramToExp, key)
		return nil, nil
	}

	return elem, nil
}

func (this *memoryDb) Save(elem *Element, exp time.Time) error {
	this.lock.Lock()
	defer this.lock.Unlock()

	// json.Marshal が非明示的に要素をソートすることに依存している。
	raw, err := json.Marshal(elem.Accounts())
	if err != nil {
		return erro.Wrap(err)
	}

	key := elem.ToTa() + string(raw)
	this.paramToElem[key] = elem
	this.paramToExp[key] = exp
	return nil
}

func (this *memoryDb) Delete(elem *Element) error {
	this.lock.Lock()
	defer this.lock.Unlock()

	// json.Marshal が非明示的に要素をソートすることに依存している。
	raw, err := json.Marshal(elem.Accounts())
	if err != nil {
		return erro.Wrap(err)
	}

	key := elem.ToTa() + string(raw)
	delete(this.paramToElem, key)
	delete(this.paramToExp, key)
	return nil
}
