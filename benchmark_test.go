// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

package syslog

import "testing"



func BenchmarkParseMessageMinimum(b *testing.B) { benchmarkParseMessage(minimumInput, b) }
func BenchmarkParseMessageRegular(b *testing.B) { benchmarkParseMessage(regularInput, b) }
func BenchmarkParseMessageLong(b *testing.B)    { benchmarkParseMessage(longInput, b) }

var Msg *Message

func benchmarkParseMessage(input []byte, b *testing.B) {
	var msg *Message
	for n := 0; n < b.N; n++ {
		msg, _ = ParseMessage(input, RFC5424)
	}
	Msg = msg
}
