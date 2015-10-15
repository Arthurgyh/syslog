// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

package syslog

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

var (
	longHostname    = generateString("hostname", maxHostnameLength)
	longAppname     = generateString("appname", maxAppNameLength)
	longProcID      = generateString("procid", maxProcessIDLength)
	longMsgID       = generateString("msgid", maxMessageIDLength)
	longDataID      = generateString("data", maxDataIDLength)
	longDataID2     = generateString("data2", maxDataIDLength)
	longParamName   = generateString("name", maxDataParamLength)
	longParamValue  = generateString("value", 1024)
	longParamName2  = generateString("name2", maxDataParamLength)
	longParamValue2 = generateString("value2", 1024)
	longMessage     = generateString("message", 1024)
	longClient      = generateString("client", 1024)
	longServer      = generateString("localhost", 1024)
	longRequest     = generateString("GET / HTTP/1.1", 1024)
	longHost        = generateString("192.168.1.254", 1024)

	minimumInputRFC5424 = []byte("<0> - - - - - -")
	regularInputRFC5424 = []byte(`<191>10 2015-09-30T23:10:11+02:00 hostname appname procid msgid [data name="value"] message`)
	longInputRFC5424    = []byte(fmt.Sprintf(`<191>99 3000-12-31T23:59:59.999999999+14:00 %s %s %s %s [%s %s=%q][%s %s=%q %s=%q] %s`,
		longHostname, longAppname, longProcID, longMsgID, longDataID, longParamName, longParamValue,
		longDataID2, longParamName, longParamValue, longParamName2, longParamValue2, longMessage))

	minimumInputNginxAccess = []byte("<190>Jan  1 01:01:01 h a: [request]")
	regularInputNginxAccess = []byte(`<190>Jan  1 01:01:01 hostname nginx: [request key="value" key2="value2" key3="value3" key4="value4" key4="value4" key5="value5"]`)
	longInputNginxAccess    = []byte(fmt.Sprintf(`<190>Dec 31 23:59:59 %s nginx: [request %s=%q %s=%q]`,
		longHostname, longParamName, longParamValue, longParamName2, longParamValue2))

	minimumInputNginxError = []byte("<184>Jan  1 01:01:01 h a: 0001/01/01 01:01:01 [Emergency] m, c: c, s: s, r: r, h: h")
	regularInputNginxError = []byte(`<186>Jan  1 01:01:01 hostname nginx: 0001/01/01 01:01:01 [Error] message, client: 192.168.1.255, server: localhost, request: "GET / HTTP/1.1", host: "192.168.1.254"`)
	longInputNginxError    = []byte(fmt.Sprintf(`<191>Dec 31 23:59:59 %s nginx: 2015/12/31 23:59:59 [Debug] %s, client: %s, server: %s, request: %q, host: %q`,
		longHostname, longMessage, longClient, longServer, longRequest, longHost))
)

func TestParseMessageRFC5424(t *testing.T) {
	t.Parallel()

	var (
		locationCEST, _ = time.LoadLocation("Europe/Amsterdam")
		locationLINT, _ = time.LoadLocation("Pacific/Kiritimati")
	)

	tests := []struct {
		Input    string
		Expected *Message
	}{
		{string(minimumInputRFC5424), &Message{}},
		{
			string(regularInputRFC5424),
			&Message{
				Priority:  CalculatePriority(Local7, Debug),
				Facility:  Local7,
				Severity:  Debug,
				Version:   10,
				Timestamp: time.Date(2015, 9, 30, 23, 10, 11, 0, locationCEST),
				Hostname:  "hostname",
				Appname:   "appname",
				ProcessID: "procid",
				MessageID: "msgid",
				Data: map[string]map[string]string{
					"data": {
						"name": "value",
					},
				},
				Message: "message",
			},
		},
		{
			`<191>10 2015-09-30T23:10:11+02:00 hostname appname procid msgid [data]`,
			&Message{
				Priority:  CalculatePriority(Local7, Debug),
				Facility:  Local7,
				Severity:  Debug,
				Version:   10,
				Timestamp: time.Date(2015, 9, 30, 23, 10, 11, 0, locationCEST),
				Hostname:  "hostname",
				Appname:   "appname",
				ProcessID: "procid",
				MessageID: "msgid",
				Data: map[string]map[string]string{
					"data": {},
				},
			},
		},
		{
			`<9>1 2000-01-01T01:01:01+00:00 h a p m [d n="v"] m`,
			&Message{
				Priority:  CalculatePriority(UserLevel, Alert),
				Facility:  UserLevel,
				Severity:  Alert,
				Version:   1,
				Timestamp: time.Date(2000, 1, 1, 1, 1, 1, 0, time.UTC),
				Hostname:  "h",
				Appname:   "a",
				ProcessID: "p",
				MessageID: "m",
				Data: map[string]map[string]string{
					"d": {
						"n": "v",
					},
				},
				Message: "m",
			},
		},
		{
			string(longInputRFC5424),
			&Message{
				Priority:  CalculatePriority(Local7, Debug),
				Facility:  Local7,
				Severity:  Debug,
				Version:   99,
				Timestamp: time.Date(3000, 12, 31, 23, 59, 59, 999999999, locationLINT),
				Hostname:  longHostname,
				Appname:   longAppname,
				ProcessID: longProcID,
				MessageID: longMsgID,
				Data: map[string]map[string]string{
					longDataID: {
						longParamName: longParamValue,
					},
					longDataID2: {
						longParamName:  longParamValue,
						longParamName2: longParamValue2,
					},
				},
				Message: longMessage,
			},
		},
	}

	for _, test := range tests {
		got, err := ParseMessage([]byte(test.Input), RFC5424)
		if err != nil {
			t.Fatalf("Unexpected error ParseMessage(%q, RFC5424): %s",
				test.Input, err.Error())
		}

		// Timestamp.Location don't compare nicely in reflect.DeepEqual, but only
		// in this function and TestParser.
		if !test.Expected.Timestamp.Equal(got.Timestamp) {
			t.Fatalf("Expected Message.Timestamp to be %v, but got %v",
				test.Expected.Timestamp, got.Timestamp)
		}
		test.Expected.Timestamp = time.Time{}
		got.Timestamp = time.Time{}

		if !reflect.DeepEqual(got, test.Expected) {
			t.Fatalf("Expected Message to be %#v, but got %#v", got, test.Expected)
		}
	}
}

func TestParseMessageNginxAccess(t *testing.T) {
	t.Parallel()

	var now = time.Now()

	tests := []struct {
		Input    string
		Expected *Message
	}{
		{
			string(minimumInputNginxAccess),
			&Message{
				Priority:  CalculatePriority(Local7, Informational),
				Facility:  Local7,
				Severity:  Informational,
				Timestamp: time.Date(now.Year(), 1, 1, 1, 1, 1, 0, now.Location()),
				Hostname:  "h",
				Appname:   "a",
				Data: map[string]map[string]string{
					"request": {},
				},
			},
		},
		{
			string(regularInputNginxAccess),
			&Message{
				Priority:  CalculatePriority(Local7, Informational),
				Facility:  Local7,
				Severity:  Informational,
				Timestamp: time.Date(now.Year(), 1, 1, 1, 1, 1, 0, now.Location()),
				Hostname:  "hostname",
				Appname:   "nginx",
				Data: map[string]map[string]string{
					"request": {
						"key":  "value",
						"key2": "value2",
						"key3": "value3",
						"key4": "value4",
						"key5": "value5",
					},
				},
			},
		},
		{
			`<190>Oct  5 12:05:15 hostname nginx: [request body_bytes_sent="612" connection="4" connection_requests="1" http_referer="-" http_user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9" http_x_forwarded_for="-" msec="1444039515.695" remote_addr="192.168.1.255" remote_user="-" request_length="451" request_time="0.000" status="200"]`,
			&Message{
				Priority:  CalculatePriority(Local7, Informational),
				Facility:  Local7,
				Severity:  Informational,
				Timestamp: time.Date(now.Year(), 10, 5, 12, 05, 15, 0, now.Location()),
				Hostname:  "hostname",
				Appname:   "nginx",
				Data: map[string]map[string]string{
					"request": {
						"body_bytes_sent":     "612",
						"connection":          "4",
						"connection_requests": "1",
						"http_user_agent":     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
						"msec":                "1444039515.695",
						"remote_addr":         "192.168.1.255",
						"request_length":      "451",
						"request_time":        "0.000",
						"status":              "200",
					},
				},
			},
		},
		{
			`<190>Oct 13 10:06:04 hostname nginx: [request body_bytes_sent="168" bytes_sent="322" connection="32" connection_requests="1" content_length="-" content_type="-" http_accept="*/*" http_accept_encoding="-" http_accept_language="-" http_content_length="-" http_content_type="-" http_host="192.168.1.254" http_origin="-" http_referer="-" http_user_agent="curl/7.43.0" http_dnt="-" http_x_do_not_track="-" http_x_requested_with="-" http_x_forwarded_host="-" http_x_forwarded_for="-" remote_addr="192.168.1.255" remote_port="54703" request_length="81" request_method="GET" request_time="0.000" sent_http_content_encoding="-" sent_http_content_language="-" sent_http_content_length="168" sent_http_location="-" status="404"]`,
			&Message{
				Priority:  CalculatePriority(Local7, Informational),
				Facility:  Local7,
				Severity:  Informational,
				Timestamp: time.Date(now.Year(), 10, 13, 10, 06, 04, 0, now.Location()),
				Hostname:  "hostname",
				Appname:   "nginx",
				Data: map[string]map[string]string{
					"request": {
						"body_bytes_sent":          "168",
						"bytes_sent":               "322",
						"connection":               "32",
						"connection_requests":      "1",
						"http_accept":              "*/*",
						"http_host":                "192.168.1.254",
						"http_user_agent":          "curl/7.43.0",
						"remote_addr":              "192.168.1.255",
						"remote_port":              "54703",
						"request_length":           "81",
						"request_method":           "GET",
						"request_time":             "0.000",
						"sent_http_content_length": "168",
						"status":                   "404",
					},
				},
			},
		},
		{
			`<190>Oct 13 17:55:29 hostname nginx: [request body_bytes_sent="168" bytes_sent="322" connection="4" connection_requests="1" content_length="-" content_type="-" remote_addr="192.168.1.255" remote_port="51999" request_length="86" request_method="GET" request_time="0.000" request_uri="/not/found" status="404" http_accept="*/*" http_accept_encoding="-" http_accept_language="-" http_content_length="-" http_content_type="-" http_host="192.168.1.254" http_origin="-" http_referer="-" http_user_agent="curl/7.43.0" http_dnt="-" http_x_do_not_track="-" http_x_requested_with="-" http_x_forwarded_host="-" http_x_forwarded_for="-" sent_http_content_encoding="-" sent_http_content_language="-" sent_http_content_length="168" sent_http_location="-"]`,
			&Message{
				Priority:  CalculatePriority(Local7, Informational),
				Facility:  Local7,
				Severity:  Informational,
				Timestamp: time.Date(now.Year(), 10, 13, 17, 55, 29, 0, now.Location()),
				Hostname:  "hostname",
				Appname:   "nginx",
				Data: map[string]map[string]string{
					"request": {
						"body_bytes_sent":          "168",
						"bytes_sent":               "322",
						"connection":               "4",
						"connection_requests":      "1",
						"http_accept":              "*/*",
						"http_host":                "192.168.1.254",
						"http_user_agent":          "curl/7.43.0",
						"remote_addr":              "192.168.1.255",
						"remote_port":              "51999",
						"request_length":           "86",
						"request_method":           "GET",
						"request_time":             "0.000",
						"request_uri":              "/not/found",
						"sent_http_content_length": "168",
						"status":                   "404",
					},
				},
			},
		},
		{
			string(longInputNginxAccess),
			&Message{
				Priority:  CalculatePriority(Local7, Informational),
				Facility:  Local7,
				Severity:  Informational,
				Timestamp: time.Date(now.Year(), 12, 31, 23, 59, 59, 0, now.Location()),
				Hostname:  longHostname,
				Appname:   "nginx",
				Data: map[string]map[string]string{
					"request": {
						longParamName:  longParamValue,
						longParamName2: longParamValue2,
					},
				},
			},
		},
	}

	for _, test := range tests {
		got, err := ParseMessage([]byte(test.Input), NginxAccess)
		if err != nil {
			t.Fatalf("Unexpected error ParseMessage(%q, NginxAccess): %s", test.Input, err.Error())
		}

		if !reflect.DeepEqual(got, test.Expected) {
			t.Fatalf("Expected Message to be %#v, but got %#v", got, test.Expected)
		}
	}
}

func TestParseMessageNginxError(t *testing.T) {
	t.Parallel()

	var now = time.Now()

	tests := []struct {
		Input    string
		Expected *Message
	}{
		{
			string(minimumInputNginxError),
			&Message{
				Priority:  CalculatePriority(Local7, Emergency),
				Facility:  Local7,
				Severity:  Emergency,
				Timestamp: time.Date(now.Year(), 1, 1, 1, 1, 1, 0, now.Location()),
				Hostname:  "h",
				Appname:   "a",
				Message:   `m`,
				Data: map[string]map[string]string{
					"data": {
						"c": "c",
						"s": "s",
						"r": "r",
						"h": "h",
					},
				},
			},
		},
		{
			string(regularInputNginxError),
			&Message{
				Priority:  CalculatePriority(Local7, Critical),
				Facility:  Local7,
				Severity:  Critical,
				Timestamp: time.Date(now.Year(), 1, 1, 1, 1, 1, 0, now.Location()),
				Hostname:  "hostname",
				Appname:   "nginx",
				Message:   `message`,
				Data: map[string]map[string]string{
					"data": {
						"client":  "192.168.1.255",
						"server":  "localhost",
						"request": "GET / HTTP/1.1",
						"host":    "192.168.1.254",
					},
				},
			},
		},
		{
			string(longInputNginxError),
			&Message{
				Priority:  CalculatePriority(Local7, Debug),
				Facility:  Local7,
				Severity:  Debug,
				Timestamp: time.Date(now.Year(), 12, 31, 23, 59, 59, 0, now.Location()),
				Hostname:  longHostname,
				Appname:   "nginx",
				Message:   longMessage,
				Data: map[string]map[string]string{
					"data": {
						"client":  longClient,
						"server":  longServer,
						"request": longRequest,
						"host":    longHost,
					},
				},
			},
		},
		{
			`<187>Oct 13 12:31:40 hostname nginx: 2015/10/13 01:31:40 [error] 1187#1187: *46 open() "/usr/share/nginx/html/test" failed (2: No such file or directory), client: 192.168.1.255, server: localhost, request: "GET /test HTTP/1.1", host: "192.168.1.254"`,
			&Message{
				Priority:  CalculatePriority(Local7, Error),
				Facility:  Local7,
				Severity:  Error,
				Timestamp: time.Date(now.Year(), 10, 13, 12, 31, 40, 0, now.Location()),
				Hostname:  "hostname",
				Appname:   "nginx",
				Message:   `1187#1187: *46 open() "/usr/share/nginx/html/test" failed (2: No such file or directory)`,
				Data: map[string]map[string]string{
					"data": {
						"client":  "192.168.1.255",
						"server":  "localhost",
						"request": "GET /test HTTP/1.1",
						"host":    "192.168.1.254",
					},
				},
			},
		},
	}

	for _, test := range tests {
		got, err := ParseMessage([]byte(test.Input), NginxError)
		if err != nil {
			t.Fatalf("Unexpected error ParseMessage(%q): %s", test.Input, err.Error())
		}

		if !reflect.DeepEqual(got, test.Expected) {
			t.Fatalf("Expected Message to be %#v, but got %#v", got, test.Expected)
		}
	}
}

func TestParser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Input    string
		Expected *Message
	}{
		{string(minimumInputRFC5424), &Message{}},
		{
			`<191>10 2015-09-30T23:10:11+00:00 hostname appname procid msgid [data]`,
			&Message{
				Priority:  CalculatePriority(Local7, Debug),
				Facility:  Local7,
				Severity:  Debug,
				Version:   10,
				Timestamp: time.Date(2015, 9, 30, 23, 10, 11, 0, time.UTC),
				Hostname:  "hostname",
				Appname:   "appname",
				ProcessID: "procid",
				MessageID: "msgid",
				Data: map[string]map[string]string{
					"data": {},
				},
			},
		},
	}

	parse := NewParser(RFC5424)

	for _, test := range tests {
		got, err := parse([]byte(test.Input))
		if err != nil {
			t.Fatalf("Unexpected error parse(%q): %s",
				test.Input, err.Error())
		}

		if !test.Expected.Timestamp.Equal(got.Timestamp) {
			t.Fatalf("Expected Message.Timestamp to be %v, but got %v",
				test.Expected.Timestamp, got.Timestamp)
		}
		test.Expected.Timestamp = time.Time{}
		got.Timestamp = time.Time{}

		if !reflect.DeepEqual(got, test.Expected) {
			t.Fatalf("Expected Message to be %#v, but got %#v", got, test.Expected)
		}
	}
}

func TestGenerateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Prefix   string
		Length   int
		Expected string
	}{
		{"", 1, "a"},
		{"", 26, "abcdefghijklmnopqrstuvwxyz"},
		{"", 52, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"},
		{"", 10, "abcdefghij"},
		{"", 80, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzab"},
		{"myPrefix", 1, "m"},
		{"myPrefix", 34, "myPrefixabcdefghijklmnopqrstuvwxyz"},
		{"myPrefix", 60, "myPrefixabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"},
		{"myPrefix", 10, "myPrefixab"},
		{"myPrefix", 80, "myPrefixabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrst"},
	}

	for _, test := range tests {
		got := generateString(test.Prefix, test.Length)

		if got != test.Expected {
			t.Fatalf("Expected generateString(%q, %d) to return %q, but got %q",
				test.Prefix, test.Length, test.Expected, got)
		}
	}
}

func generateString(prefix string, length int) string {
	var str = prefix
	for len(str) < length {
		str += "abcdefghijklmnopqrstuvwxyz"
	}
	return str[:length]
}
