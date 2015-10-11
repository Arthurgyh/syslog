// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

package syslog

import (
	"fmt"
	"testing"
)

var (
	longHostname    = generateString("hostname", maxHostnameLength)
	longAppname     = generateString("appname", maxAppNameLength)
	longProcID      = generateString("procid", maxProcessIDLength)
	longMsgID       = generateString("msgid", maxMessageIDLength)
	longDataID      = generateString("data", maxDataIDLength)
	longParamName   = generateString("name", maxDataParamLength)
	longParamValue  = generateString("value", 1024)
	longDataID2     = generateString("data", maxDataIDLength)
	longParamName2  = generateString("name", maxDataParamLength)
	longParamValue2 = generateString("value", 1024)
	longMessage     = generateString("message", 1024)

	minimumInput = []byte("<0> - - - - - -")
	regularInput = []byte(`<191>10 2015-09-30T23:10:11+02:00 hostname appname procid msgid [data name="value"] message`)
	longInput    = []byte(fmt.Sprintf(`<191>99 3000-12-31T23:59:59.999999999+14:00 %s %s %s %s [%s %s=%q][%s %s=%q %s=%q] %s`,
		longHostname, longAppname, longProcID, longMsgID, longDataID, longParamName, longParamValue,
		longDataID2, longParamName, longParamValue, longParamName2, longParamValue2, longMessage))
)

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
