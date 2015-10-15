// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed under the MIT license that can be found in the LICENSE file.

package syslog

import (
	"io"
	"testing"
)

func TestBuffer(t *testing.T) {
	t.Parallel()

	var msg = []byte("This is the very, very usefull message")

	buf := newBuffer(msg)

	if b, err := buf.Peek(4); err != nil {
		t.Fatalf("Unexpected error buf.Peek(4): %s", err.Error())
	} else if expected, got := "This", string(b); got != expected {
		t.Fatalf("Expected buf.Peek(4) to return %s, but got %s", expected, got)
	}

	if expected, got := 5, buf.Discard(5); got != expected {
		t.Fatalf("Expected buf.Discard(5) to return %d, but got %d", expected, got)
	}

	if c, err := buf.ReadByte(); err != nil {
		t.Fatalf("Unexpected error buf.ReadByte(): %s", err.Error())
	} else if expected, got := byte('i'), c; got != expected {
		t.Fatalf("Expected buf.ReadByte() to return %v, but got %s",
			string(expected), string(got))
	}
	buf.UnreadByte()

	if b, err := buf.ReadSlice(' '); err != nil {
		t.Fatalf("Unexpected error buf.ReadSlice(' '): %s", err.Error())
	} else if expected, got := "is ", string(b); got != expected {
		t.Fatalf("Expected buf.ReadSlice(' ') to return %s, but got %s", expected, got)
	}

	if b, err := buf.Peek(100); err != io.EOF {
		t.Fatalf("Expected buf.Peek(100) to return error %s, but got %s", err.Error(), err)
	} else if expected, got := "the very, very usefull message", string(b); got != expected {
		t.Fatalf("Expected buf.Peek(100) to return %s, but got %s", expected, got)
	}

	if expected, got := "the very, very usefull message", string(buf.ReadAll()); got != expected {
		t.Fatalf("Expected buf.ReadAll() to return %s, but got %s", expected, got)
	}
}
