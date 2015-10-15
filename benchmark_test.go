// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed under the MIT license that can be found in the LICENSE file.

package syslog

import "testing"

func BenchmarkParseRFC5424Minimum(b *testing.B) { benchPM(minimumInputRFC5424, RFC5424, b) }
func BenchmarkParseRFC5424Regular(b *testing.B) { benchPM(regularInputRFC5424, RFC5424, b) }
func BenchmarkParseRFC5424Long(b *testing.B)    { benchPM(longInputRFC5424, RFC5424, b) }

func BenchmarkParseNginxAccessMinimum(b *testing.B) { benchPM(minimumInputNginxAccess, NginxAccess, b) }
func BenchmarkParseNginxAccessRegular(b *testing.B) { benchPM(regularInputNginxAccess, NginxAccess, b) }
func BenchmarkParseNginxAccessLong(b *testing.B)    { benchPM(longInputNginxAccess, NginxAccess, b) }

func BenchmarkParseNginxErrorMinimum(b *testing.B) { benchPM(minimumInputNginxError, NginxError, b) }
func BenchmarkParseNginxErrorRegular(b *testing.B) { benchPM(regularInputNginxError, NginxError, b) }
func BenchmarkParseNginxErrorLong(b *testing.B)    { benchPM(longInputNginxError, NginxError, b) }

var Msg *Message

// Benchmark parse message.
func benchPM(input []byte, format format, b *testing.B) {
	var msg *Message
	for n := 0; n < b.N; n++ {
		msg, _ = ParseMessage(input, format)
	}
	Msg = msg
}
