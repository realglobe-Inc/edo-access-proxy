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

const (
	test_id     = "Xewtmrlnu5HVDzem5rmyGzoe2edQjI"
	test_toTa   = "https://ta.example.org"
	test_tokTag = "HcmmhWaXLE"
	test_idp    = "https://ta.example.org"
	test_acntId = "https://ta.example.org"
)

var (
	test_acnts = map[string]*Account{
		"tester": NewMainAccount(test_tokTag),
		"user":   NewSubAccount(test_idp, test_acntId),
	}
)
