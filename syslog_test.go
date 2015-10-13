// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

package syslog

import (
	"fmt"
	"testing"
	"time"
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
		{"<0> - - - - - -", &Message{}},
		{
			`<191>10 2015-09-30T23:10:11+02:00 hostname appname procid msgid [data name="value"] message`,
			&Message{
				Priority:  Priority(191),
				Facility:  Facility(23),
				Severity:  Severity(7),
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
			`<9>1 2000-01-01T01:01:01+00:00 h a p m [d n="v"] m`,
			&Message{
				Priority:  Priority(9),
				Facility:  Facility(1),
				Severity:  Severity(1),
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
			fmt.Sprintf(`<191>99 3000-12-31T23:59:59.999999999+14:00 %s %s %s %s [%s %s=%q][%s %s=%q %s=%q] %s`,
				longHostname, longAppname, longProcID, longMsgID, longDataID, longParamName, longParamValue,
				longDataID2, longParamName, longParamValue, longParamName2, longParamValue2, longMessage),
			&Message{
				Priority:  Priority(191),
				Facility:  Facility(23),
				Severity:  Severity(7),
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
			t.Fatalf("Unexpected error ParseMessage(%q): %s", test.Input, err.Error())
		}
		expected := test.Expected

		if err := testEqualMessage(got, expected); err != nil {
			t.Fatal(err.Error())
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
			`<190>Oct 10 12:05:15 hostname nginx: [request body_bytes_sent="612" connection="4" connection_requests="1" http_referer="-" http_user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9" http_x_forwarded_for="-" msec="1444039515.695" remote_addr="192.168.1.255" remote_user="-" request_length="451" request_time="0.000" status="200"]`,
			&Message{
				Priority:  CalculatePriority(Local7, Informational),
				Facility:  Local7,
				Severity:  Informational,
				Timestamp: time.Date(now.Year(), 10, 10, 12, 05, 15, 0, now.Location()),
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
	}

	for _, test := range tests {
		got, err := ParseMessage([]byte(test.Input), NginxAccess)
		if err != nil {
			t.Fatalf("Unexpected error ParseMessage(%q): %s", test.Input, err.Error())
		}
		expected := test.Expected

		if err := testEqualMessage(got, expected); err != nil {
			t.Fatal(err.Error())
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
		// todo: add more error messages.
		{
			`<187>Oct 13 12:31:40 hostname nginx: 2015/10/13 01:31:40 [error] 1187#1187: *46 open() "/usr/share/nginx/html/test" failed (2: No such file or directory), client: 192.168.1.255, server: localhost, request: "GET /test HTTP/1.1", host: "192.168.1.254"`,
			&Message{
				Priority:  Priority(187),
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
		expected := test.Expected

		if err := testEqualMessage(got, expected); err != nil {
			t.Fatal(err.Error())
		}
	}
}

func testEqualMessage(got, expected *Message) error {
	if expected.Priority != got.Priority {
		return fmt.Errorf("Expected Message.Priority to be %v, but got %v",
			expected.Priority, got.Priority)
	} else if expected.Facility != got.Facility {
		return fmt.Errorf("Expected Message.Facility to be %v, but got %v",
			expected.Facility, got.Facility)
	} else if expected.Severity != got.Severity {
		return fmt.Errorf("Expected Message.Severity to be %v, but got %v",
			expected.Severity, got.Severity)
	} else if expected.Version != got.Version {
		return fmt.Errorf("Expected Message.Version to be %v, but got %v",
			expected.Version, got.Version)
	} else if !expected.Timestamp.Equal(got.Timestamp) {
		return fmt.Errorf("Expected Message.Timestamp to be %v, but got %v",
			expected.Timestamp, got.Timestamp)
	} else if expected.Hostname != got.Hostname {
		return fmt.Errorf("Expected Message.Hostname to be %v, but got %v",
			expected.Hostname, got.Hostname)
	} else if expected.Appname != got.Appname {
		return fmt.Errorf("Expected Message.Appname to be %v, but got %v",
			expected.Appname, got.Appname)
	} else if expected.ProcessID != got.ProcessID {
		return fmt.Errorf("Expected Message.ProcessID to be %v, but got %v",
			expected.ProcessID, got.ProcessID)
	} else if expected.MessageID != got.MessageID {
		return fmt.Errorf("Expected Message.MessageID to be %v, but got %v",
			expected.MessageID, got.MessageID)
	} else if expected.Message != got.Message {
		return fmt.Errorf("Expected Message.Message to be %v, but got %v",
			expected.Message, got.Message)
	}

	if len(got.Data) != len(expected.Data) {
		return fmt.Errorf("Expected Message.Data to be %#v, but got %#v",
			expected.Data, got.Data)
	}

	for dataID, m := range got.Data {
		em, ok := expected.Data[dataID]
		if !ok || len(m) != len(em) {
			return fmt.Errorf("Expected Message.Data to be %#v, but got %#v",
				expected.Data, got.Data)
		}

		for paramName, gotValue := range m {
			expectedValue, ok := em[paramName]
			if !ok || gotValue != expectedValue {
				return fmt.Errorf("Expected Message.Data to be %#v, but got %#v",
					expected.Data, got.Data)
			}
		}
	}

	return nil
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
