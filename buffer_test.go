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

	if expected, got := "the very, very usefull message", string(buf.ReadAll()); got != expected {
		t.Fatalf("Expected buf.ReadAll() to return %s, but got %s", expected, got)
	}
}

func TestBufferDiscardTooMuch(t *testing.T) {
	t.Parallel()

	var msg = []byte("Some message")
	buf := newBuffer(msg)

	expected := len(msg)
	discardLength := len(msg) + 1
	n := buf.Discard(discardLength)

	if n != expected {
		t.Fatal("Expected buf.Discard(%d) to return %d, but got %d",
			discardLength, expected, n)
	}
}

func TestBufferPeekToomuch(t *testing.T) {
	t.Parallel()

	var msg = []byte("Some message")
	buf := newBuffer(msg)

	expected := "Some message"
	peekLength := len(msg) + 1
	b, err := buf.Peek(peekLength)
	if err != io.EOF {
		t.Fatalf("Expected buf.Peek(%d) to return error %s, but got %s",
			peekLength, io.EOF.Error(), err.Error())
	} else if got := string(b); got != expected {
		t.Fatalf("Expected buf.Peek(%d) to return %s, but got %s", peekLength, expected, got)
	}
}

func TestBufferReadLastByte(t *testing.T) {
	t.Parallel()

	buf := newBuffer([]byte{})

	c, err := buf.ReadByte()
	if err != io.EOF {
		t.Fatalf("Expected buf.ReadByte() to return error %s, but got %s", io.EOF, err.Error())
	} else if c != 0 {
		t.Fatalf("Expected buf.ReadByte() to return 0, but got %q", string(c))
	}
}

func TestBufferFirstUnreadByte(t *testing.T) {
	t.Parallel()

	buf := newBuffer([]byte{})

	defer func() {
		recv := recover()
		if recv == nil {
			t.Fatal("Expected a panic, but didn't get any")
		}

		got := recv.(string)
		expected := "syslog: can't unread byte"
		if got != expected {
			t.Fatal("Expected panic value to be %q, but got %q", expected, got)
		}
	}()

	buf.UnreadByte()
}

func TestBufferReadSliceNotFound(t *testing.T) {
	t.Parallel()

	var msg = []byte("Some-very-long-message-without-spaces")
	buf := newBuffer(msg)

	expected := "Some-very-long-message-without-spaces"
	b, err := buf.ReadSlice(' ')
	if err != io.EOF {
		t.Fatalf("Expected buf.ReadSlice(' ') to return error %s, but got %s",
			io.EOF.Error(), err.Error())
	} else if got := string(b); got != expected {
		t.Fatalf("Expected buf.ReadSlice(' ') to return %s, but got %s",
			expected, got)
	}
}
