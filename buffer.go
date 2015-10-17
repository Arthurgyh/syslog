// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed under the MIT license that can be found in the LICENSE file.

package syslog

import "io"

// Note: not safe for concurrent use!
type buffer struct {
	bytes    []byte // Do not modify.
	length   int    // Do not modify.
	position int
}

func (buf *buffer) Discard(n int) (discarded int) {
	if max := buf.maxRead(); n > max {
		n = max
	}
	buf.position += n
	return n
}

func (buf *buffer) Peek(n int) ([]byte, error) {
	var err error
	if max := buf.maxRead(); n > max {
		n = max
		err = io.EOF
	}
	return buf.bytes[buf.position : buf.position+n], err
}

func (buf *buffer) ReadByte() (byte, error) {
	if buf.position == buf.length {
		return 0, io.EOF
	}
	c := buf.bytes[buf.position]
	buf.position++
	return c, nil
}

func (buf *buffer) UnreadByte() {
	if buf.position == 0 {
		panic("syslog: can't unread byte")
	}
	buf.position--
}

func (buf *buffer) ReadSlice(c byte) ([]byte, error) {
	for i, cc := range buf.bytes[buf.position:] {
		if cc == c {
			end := buf.position + i + 1
			bytes := buf.bytes[buf.position:end]
			buf.position = end
			return bytes, nil
		}
	}

	n := buf.position
	buf.position = buf.length
	return buf.bytes[n:], io.EOF
}

func (buf *buffer) ReadAll() []byte {
	bytes := buf.bytes[buf.position:]
	buf.position = buf.length
	return bytes
}

func (buf *buffer) maxRead() int {
	return buf.length - buf.position
}

func newBuffer(b []byte) *buffer {
	return &buffer{
		bytes:  b,
		length: len(b),
	}
}
