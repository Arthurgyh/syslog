package syslog

import (
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type ParseFuncTest struct {
	Input         string
	Expected      *Message
	ExpectedError error
}

func TestParsePriority(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"<0>", &Message{Priority: 0}, nil},
		{"<1>", &Message{Priority: 1}, nil},
		{"<100>", &Message{Priority: 100}, nil},
		{"<191>", &Message{Priority: 191}, nil},

		{"", nil, io.EOF},
		{"!", nil, newFormatError(1, "expected byte '<', but got '!'")},
		{"<1923", nil, newFormatError(5, "priority not closed")},
		{"<19", nil, newFormatError(3, "priority not closed")},
		{"<1923>", nil, newFormatError(5, "priority too long")},
		{"<>", nil, newFormatError(2, "priority can't be empty")},
		{"<abc>", nil, newFormatError(2, "priority not a number: abc")},
	}

	if err := testParseFunc(parsePriority, tests); err != nil {
		t.Fatal(err)
	}
}

func testParseFunc(fn parseFunc, tests []ParseFuncTest) error {
	for _, test := range tests {
		buf := newBuffer([]byte(test.Input))
		gotMsg := Message{}
		gotErr := fn(buf, &gotMsg)

		if gotErr != nil {
			if test.ExpectedError == nil {
				return fmt.Errorf("Unexpected error calling %s(%q) %s", getFuncName(fn),
					test.Input, gotErr)
			} else if gotErr.Error() != test.ExpectedError.Error() {
				return fmt.Errorf("Expected %s(%q) to return error %q, but got %q",
					getFuncName(fn), test.Input, test.ExpectedError.Error(), gotErr.Error())
			} else {
				// Expected an error and they match, don't need to test syslog.Message.
				continue
			}
		} else if test.ExpectedError != nil {
			return fmt.Errorf("Expected %s(%q) to return error %q, but got nil",
				getFuncName(fn), test.Input, test.ExpectedError.Error())
		}

		if !messagesAreEqual(&gotMsg, test.Expected) {
			return fmt.Errorf("Expected %s(%q) to return Message %#v, but got %#v",
				getFuncName(fn), test.Input, test.Expected, gotMsg)
		}
	}

	return nil
}

func getFuncName(fn parseFunc) string {
	prt := reflect.ValueOf(fn).Pointer()
	fullName := runtime.FuncForPC(prt).Name()
	return strings.TrimPrefix(fullName, "github.com/Thomasdezeeuw/syslog.")
}
