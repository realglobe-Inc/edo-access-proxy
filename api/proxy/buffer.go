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
	"bufio"
	"bytes"
	"github.com/realglobe-Inc/go-lib/erro"
	"io"
	"io/ioutil"
	"os"
)

// ボディを読みながら保存しとく機構
type buffer struct {
	base io.ReadCloser

	last bool

	memMax int
	memW   *bytes.Buffer
	memR   *bytes.Reader

	filePref string
	file     *os.File
	fileW    *bufio.Writer
	fileR    *bufio.Reader
}

func newBuffer(base io.ReadCloser, memMax int, filePref string) *buffer {
	return &buffer{
		base:     base,
		memMax:   memMax,
		memW:     &bytes.Buffer{},
		filePref: filePref,
	}
}

func (this *buffer) Read(p []byte) (n int, err error) {
	n = 0
	if this.memR != nil {
		m, err := io.ReadFull(this.memR, p[n:])
		switch err {
		case nil:
			// バッファが埋まった。
			return n + m, nil
		case io.EOF, io.ErrUnexpectedEOF:
			// メモリを読み切った。
			n += m
			this.memR = nil
		default:
			// 読み込みエラー。
			return 0, erro.Wrap(err)
		}
	}
	if this.fileR != nil {
		m, err := io.ReadFull(this.fileR, p[n:])
		switch err {
		case nil:
			// バッファが埋まった。
			return n + m, nil
		case io.EOF, io.ErrUnexpectedEOF:
			// ファイルを読み切った。
			n += m
			this.fileR = nil
		default:
			// 読み込みエラー。
			return 0, erro.Wrap(err)
		}
	}
	if this.base != nil {
		m, err := io.ReadFull(this.base, p[n:])
		switch err {
		case nil:
			// バッファが埋まった。
			if err := this.save(p[n : n+m]); err != nil {
				return 0, erro.Wrap(err)
			}
			return n + m, nil
		case io.EOF, io.ErrUnexpectedEOF:
			// ボディを読み切った。
			if err := this.save(p[n : n+m]); err != nil {
				return 0, erro.Wrap(err)
			}
			n += m
			this.base.Close()
			this.base = nil
		default:
			// 読み込みエラー。
			return 0, erro.Wrap(err)
		}
	}

	return n, io.EOF
}

// 貯める。
func (this *buffer) save(data []byte) (err error) {
	if this.last {
		return nil
	}
	if this.fileW == nil {
		// メモリに貯められるだけ貯める。
		if remSize := this.memMax - this.memW.Len(); remSize > 0 {
			toSave := data
			if len(toSave) > remSize {
				toSave = data[:remSize]
			}
			saveLen, _ := this.memW.Write(toSave)
			data = data[saveLen:]
		}
		if len(data) == 0 {
			return nil
		}

		if this.file == nil {
			this.file, err = ioutil.TempFile("", this.filePref)
			if err != nil {
				return erro.Wrap(err)
			}
		}
		this.fileW = bufio.NewWriter(this.file)
	}

	// ファイルに貯める。
	if _, err := this.fileW.Write(data); err != nil {
		return erro.Wrap(err)
	}
	return nil
}

func (this *buffer) Close() error {
	return nil
}

// 最後の 1 回。
func (this *buffer) lastRollback() error {
	if err := this.rollback(); err != nil {
		return erro.Wrap(err)
	}
	this.setLast()
	return nil
}

// また頭から読めるようにする。
func (this *buffer) rollback() error {
	if this.last {
		return erro.New("last stage")
	}
	if this.file != nil {
		if this.fileW != nil {
			if err := this.fileW.Flush(); err != nil {
				return erro.Wrap(err)
			}
			this.fileW = nil
		}
		if _, err := this.file.Seek(0, 0); err != nil {
			return erro.Wrap(err)
		}
		this.fileR = bufio.NewReader(this.file)
	}
	if this.memW != nil {
		this.memR = bytes.NewReader(this.memW.Bytes())
	}
	return nil
}

// もう貯めないようにする。
func (this *buffer) setLast() {
	this.last = true
}

// 廃棄する。
func (this *buffer) dispose() {
	if this.file != nil {
		this.file.Close()
		os.Remove(this.file.Name())
	}
	if this.base != nil {
		this.base.Close()
	}
}
