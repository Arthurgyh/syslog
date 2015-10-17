// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed under the MIT license that can be found in the LICENSE file.

package syslog

import "io"

// Buffer is our own custom buffer implementation.
// Note: not safe for concurrent use!
type buffer struct {
	bytes    []byte // Do not modify.
	length   int    // Do not modify.
	position int
}

// Discard discards the given number of bytes. It returns the number of given
// bytes discarded.
func (buf *buffer) Discard(n int) (discarded int) {
	if max := buf.maxRead(); n > max {
		n = max
	}
	buf.position += n
	return n
}

// Peek peeks the next number of bytes. It only returns an io.EOF error if the
// peek length is greater then the number of bytes remaining.
func (buf *buffer) Peek(n int) ([]byte, error) {
	var err error
	if max := buf.maxRead(); n > max {
		n = max
		err = io.EOF
	}
	return buf.bytes[buf.position : buf.position+n], err
}

// Readbyte reads a single byte. It only returns an io.EOF error if the buffer
// is completely read.
func (buf *buffer) ReadByte() (byte, error) {
	if buf.position == buf.length {
		return 0, io.EOF
	}
	c := buf.bytes[buf.position]
	buf.position++
	return c, nil
}

// UnreadByte unreads a single byte, it panics if no bytes were read before.
func (buf *buffer) UnreadByte() {
	if buf.position == 0 {
		panic("syslog: can't unread byte")
	}
	buf.position--
}

// ReadSlice reads until the first appears of the given char. If the character
// is not found it returns the remaing buffer and an io.EOF.
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

// ReadAll returns the remaining bytes in the buffer.
func (buf *buffer) ReadAll() []byte {
	bytes := buf.bytes[buf.position:]
	buf.position = buf.length
	return bytes
}

// MaxRead return the maximum number of bytes we can read, aka the number of
// remaining bytes.
func (buf *buffer) maxRead() int {
	return buf.length - buf.position
}

// NewBuffer creates a new buffer.
func newBuffer(b []byte) *buffer {
	return &buffer{
		bytes:  b,
		length: len(b),
	}
}
