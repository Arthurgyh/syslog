package syslog

import (
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type ParseFuncTest struct {
	Input            string
	Expected         *Message
	ExpectedError    error
	ExpectedLeftover string
}

func TestParsePriority(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"<0>", &Message{Priority: 0}, nil, ""},
		{"<1>", &Message{Priority: 1}, nil, ""},
		{"<100>", &Message{Priority: 100}, nil, ""},
		{"<191>", &Message{Priority: 191}, nil, ""},

		{"", nil, io.EOF, ""},
		{"!", nil, newFormatError(1, "expected byte '<', but got '!'"), ""},
		{"<1923", nil, newFormatError(5, "priority not closed"), ""},
		{"<19", nil, newFormatError(3, "priority not closed"), ""},
		{"<1923>", nil, newFormatError(5, "priority too long"), ""},
		{"<>", nil, newFormatError(2, "priority can't be empty"), ""},
		{"<abc>", nil, newFormatError(2, "priority not a number: abc"), ""},
	}

	if err := testParseFunc(parsePriority, tests); err != nil {
		t.Fatal(err)
	}
}

func TestParseVersion(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, nil, ""},
		{"0", &Message{Version: 0}, nil, ""},
		{"1", &Message{Version: 1}, nil, ""},
		{"10", &Message{Version: 10}, nil, ""},
		{"99", &Message{Version: 99}, nil, ""},

		{"a", nil, newFormatError(1, "version not a number: a"), ""},
		{"ab", nil, newFormatError(1, "version not a number: ab"), ""},
	}

	if err := testParseFunc(parseVersion, tests); err != nil {
		t.Fatal(err)
	}
}

func TestParseTimestamp(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"-", &Message{}, nil, ""},
		{"2015-10-18T17:05:55+00:00", &Message{Timestamp: time.Date(2015, 10, 18, 17, 5, 55, 0, time.UTC)}, nil, ""},
		{"2015-10-18T17:05:55+02:00", &Message{Timestamp: time.Date(2015, 10, 18, 17, 5, 55, 0, locationCEST)}, nil, ""},
		{"2015-10-18T17:05:55.956934919+02:00", &Message{Timestamp: time.Date(2015, 10, 18, 17, 5, 55, 956934919, locationCEST)}, nil, ""},

		{"a", nil, newFormatError(1, "timestamp is not following an accepted format"), ""},
		{"abc", nil, newFormatError(1, "timestamp is not following an accepted format"), ""},
	}

	if err := testParseFunc(parseTimestamp(time.RFC3339, time.RFC3339Nano), tests); err != nil {
		t.Fatal(err)
	}
}

func TestParseTimestampNoTimestamps(t *testing.T) {
	t.Parallel()

	defer func() {
		recv := recover()
		if recv == nil {
			t.Fatal("Expected parseTimestamp() to panic, but it didn't")
		}
		expected := "syslog: no formats supplied to parseTimestamp"
		got, ok := recv.(string)
		if !ok {
			t.Fatalf("Unexpected panic: %v", recv)
		}

		if got != expected {
			t.Fatalf("Expected parseTimestamp() to panic with message %s, but got %s",
				expected, got)
		}
	}()

	parseTimestamp()
}

func TestParseHostname(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, io.EOF, ""},
		{"-", &Message{Hostname: ""}, nil, ""},
		{"h", &Message{Hostname: "h"}, nil, ""},
		{"host", &Message{Hostname: "host"}, nil, ""},
		{"hostname ", &Message{Hostname: "hostname"}, nil, " "},

		{generateString("hostname", maxHostnameLength+1), nil, newFormatError(1, "hostname too long"), ""},
	}

	if err := testParseFunc(parseHostname, tests); err != nil {
		t.Fatal(err)
	}
}

func TestParseAppname(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, io.EOF, ""},
		{"-", &Message{Appname: ""}, nil, ""},
		{"a", &Message{Appname: "a"}, nil, ""},
		{"app", &Message{Appname: "app"}, nil, ""},
		{"appname ", &Message{Appname: "appname"}, nil, " "},

		{generateString("appname", maxAppNameLength+1), nil, newFormatError(1, "appname too long"), ""},
	}

	if err := testParseFunc(parseAppname, tests); err != nil {
		t.Fatal(err)
	}
}

func TestParseProcessID(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, io.EOF, ""},
		{"-", &Message{ProcessID: ""}, nil, ""},
		{"p", &Message{ProcessID: "p"}, nil, ""},
		{"procId", &Message{ProcessID: "procId"}, nil, ""},
		{"processID ", &Message{ProcessID: "processID"}, nil, " "},

		{generateString("processID", maxHostnameLength+1), nil, newFormatError(1, "processID too long"), ""},
	}

	if err := testParseFunc(parseProcessID, tests); err != nil {
		t.Fatal(err)
	}
}

func TestParseMessageID(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, io.EOF, ""},
		{"-", &Message{MessageID: ""}, nil, ""},
		{"m", &Message{MessageID: "m"}, nil, ""},
		{"msgID", &Message{MessageID: "msgID"}, nil, ""},
		{"messageID ", &Message{MessageID: "messageID"}, nil, " "},

		{generateString("messageID", maxHostnameLength+1), nil, newFormatError(1, "messageID too long"), ""},
	}

	if err := testParseFunc(parseMessageID, tests); err != nil {
		t.Fatal(err)
	}
}

func TestParseData(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, io.EOF, ""},
		{"-", &Message{}, nil, ""},
		{`[dataID]`, &Message{Data: map[string]map[string]string{"dataID": {}}}, nil, ""},
		{`[dataID dataName="dataValue"]`, &Message{Data: map[string]map[string]string{"dataID": {"dataName": "dataValue"}}}, nil, ""},
		{`[dataID dataName="dataValue" dataName2="dataValue2"]`, &Message{Data: map[string]map[string]string{"dataID": {"dataName": "dataValue", "dataName2": "dataValue2"}}}, nil, ""},
	}

	if err := testParseFunc(parseData, tests); err != nil {
		t.Fatal(err)
	}
}

func TestParseMsg(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, nil, ""},
		{"m", &Message{Message: "m"}, nil, ""},
		{"msg", &Message{Message: "msg"}, nil, ""},
		{" message ", &Message{Message: "message"}, nil, ""},
		{string(bom) + " message ", &Message{Message: "message"}, nil, ""},
		{" \t\t message \t\t ", &Message{Message: "message"}, nil, ""},
		{" \t\t " + string(bom) + "message \t\t ", &Message{Message: "message"}, nil, ""},
	}

	if err := testParseFunc(parseMsg, tests); err != nil {
		t.Fatal(err)
	}
}

func TestDiscard(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, io.EOF, ""},
		{"1234", &Message{}, io.EOF, ""},
		{"12345", &Message{}, nil, ""},
		{"123456", &Message{}, nil, "6"},
	}

	if err := testParseFunc(discard(5), tests); err != nil {
		t.Fatal(err)
	}
}

func TestDiscardByte(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, io.EOF, ""},
		{"a", &Message{}, nil, ""},
		{"abc", &Message{}, nil, "bc"},

		{"bc", &Message{}, newFormatError(1, "expected byte 'a', but got 'b'"), ""},
		{"cba", &Message{}, newFormatError(1, "expected byte 'a', but got 'c'"), ""},
	}

	if err := testParseFunc(discardByte('a'), tests); err != nil {
		t.Fatal(err)
	}
}

func TestDiscardUntil(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, io.EOF, ""},
		{"bcdef", &Message{}, io.EOF, ""},
		{"a", &Message{}, nil, ""},
		{"abc", &Message{}, nil, "bc"},
		{"cba", &Message{}, nil, ""},
	}

	if err := testParseFunc(discardUntil('a'), tests); err != nil {
		t.Fatal(err)
	}
}

func TestDiscardSpace(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, io.EOF, ""},
		{" ", &Message{}, nil, ""},
		{" abc", &Message{}, nil, "abc"},

		{"bc", &Message{}, newFormatError(1, "expected byte ' ', but got 'b'"), ""},
		{"cb ", &Message{}, newFormatError(1, "expected byte ' ', but got 'c'"), ""},
	}

	if err := testParseFunc(discardSpace, tests); err != nil {
		t.Fatal(err)
	}
}

func TestParseNginxMsg(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"", &Message{}, io.EOF, ""},
		{"msg", &Message{}, io.EOF, ""},
		{"msg,", &Message{Message: "msg"}, nil, ""},
		{" message ,", &Message{Message: "message"}, nil, ""},
	}

	if err := testParseFunc(parseNginxMsg, tests); err != nil {
		t.Fatal(err)
	}
}

func TestParseNginxData(t *testing.T) {
	t.Parallel()

	tests := []ParseFuncTest{
		{"a:", &Message{Data: map[string]map[string]string{"data": {"a": ""}}}, nil, ""},
		{"a: a", &Message{Data: map[string]map[string]string{"data": {"a": "a"}}}, nil, ""},
		{"a : a, b : b", &Message{Data: map[string]map[string]string{"data": {"a": "a", "b": "b"}}}, nil, ""},
		{`"a": a, abc: "a b c"`, &Message{Data: map[string]map[string]string{"data": {"a": "a", "abc": "a b c"}}}, nil, ""},
		{`" a ": a , " abc ": " a b c "`, &Message{Data: map[string]map[string]string{"data": {" a ": "a", " abc ": " a b c "}}}, nil, ""},
		{`"a b": "a b", abc: "a b c" `, &Message{Data: map[string]map[string]string{"data": {"a b": "a b", "abc": "a b c"}}}, nil, ""},
		{`"a:b": "c,b"`, &Message{Data: map[string]map[string]string{"data": {"a:b": "c,b"}}}, nil, ""},
		{`a: a, d: "\"d\""`, &Message{Data: map[string]map[string]string{"data": {"a": "a", "d": `"d"`}}}, nil, ""},

		{"", &Message{}, io.EOF, ""},
		{"a: a, b", &Message{}, io.EOF, ""},
	}

	if err := testParseFunc(parseNginxData, tests); err != nil {
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

		gotLeftover := string(buf.ReadAll())
		if gotLeftover != test.ExpectedLeftover {
			return fmt.Errorf("Expected leftover bytes to be %q, but got %q",
				test.ExpectedLeftover, gotLeftover)
		}
	}

	return nil
}

func getFuncName(fn parseFunc) string {
	prt := reflect.ValueOf(fn).Pointer()
	fullName := runtime.FuncForPC(prt).Name()
	return strings.TrimPrefix(fullName, "github.com/Thomasdezeeuw/syslog.")
}
