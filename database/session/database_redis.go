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
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/realglobe-Inc/go-lib/erro"
)

type redisDb struct {
	pool *redis.Pool
	tag  string
}

// redis によるセッションの格納庫。
func NewRedisDb(pool *redis.Pool, tag string) Db {
	return &redisDb{
		pool: pool,
		tag:  tag,
	}
}

func (this *redisDb) GetByToTa(toTa string) (*Element, error) {
	conn := this.pool.Get()
	defer conn.Close()

	data, err := redis.Bytes(conn.Do("GET", this.tag+toTa))
	if err != nil {
		if err == redis.ErrNil {
			// 無かった。
			return nil, nil
		}
		return nil, erro.Wrap(err)
	}

	var buff struct {
		Id  string
		Exp time.Time
	}
	if err := json.Unmarshal(data, &buff); err != nil {
		return nil, erro.Wrap(err)
	}
	return New(buff.Id, buff.Exp, toTa), nil
}

func (this *redisDb) Save(elem *Element, exp time.Time) error {
	conn := this.pool.Get()
	defer conn.Close()

	data, err := json.Marshal(map[string]interface{}{
		"id":  elem.Id(),
		"exp": elem.Expires(),
	})
	if err != nil {
		return erro.Wrap(err)
	}

	expIn := int64(exp.Sub(time.Now()) / time.Millisecond)
	if _, err := conn.Do("SET", this.tag+elem.ToTa(), data, "PX", expIn); err != nil {
		return erro.Wrap(err)
	}

	return nil
}

func (this *redisDb) Delete(elem *Element) error {
	conn := this.pool.Get()
	defer conn.Close()

	if _, err := conn.Do("DEL", this.tag+elem.ToTa()); err != nil {
		return erro.Wrap(err)
	}

	return nil
}
