// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

package syslog

import "time"

type format []parseFunc

var (
	// RFC5424 is the format specified in RFC 5424. See
	// https://tools.ietf.org/html/rfc5424 for more information.
	RFC5424 = rfc5424Format

	// NginxAccess is the format to parse Nginx syslog access logs. To allow the
	// Message.Data to be filled the following logformat is required to be used:
	//
	//	log_format syslog '[request '
	//		'variable="$variable" '
	//		'variable2="$variable2" '
	// 		']';
	//
	// For example:
	//
	//	log_format syslog '[request '
	//		'remote_addr="$remote_addr" '
	//		'request_time="$request_time" '
	//		'status="$status"'
	// 		']';
	//
	// Using this log_format allows the Message.Data["Request"] to be filled with
	// the data from Nginx. Using the above log_format we can access the status
	// using Message.Data["Request"]["status"].
	NginxAccess = nginxAccessFormat

	// NginxError is the format to parse Nginx syslog error logs.
	NginxError = nginxErrorFormat
)

// Format: <191>10 2015-09-30T23:10:11+02:00 hostname appname procid msgid [data name="value"] message.
var rfc5424Format = format{
	parsePriority,     //<191>
	calculateFacility, //
	calculateSeverity, //
	parseVersion,      //10
	discardSpace,
	parseTimestamp(time.RFC3339, time.RFC3339Nano), // 2015-09-30T23:10:11+02:00
	discardSpace,
	parseHostname, // hostname
	discardSpace,
	parseAppname, // appname
	discardSpace,
	parseProcessID, // procid
	discardSpace,
	parseMessageID, // msgid
	discardSpace,
	parseData,                           // [data name="value"]
	optional(2, discardSpace, parseMsg), // message
}

// Format: <190>Oct  5 12:05:15 hostname nginx: [request remote_addr="192.168.1.255" status="200"].
var nginxAccessFormat = format{
	parsePriority, // <190>
	calculateFacility,
	calculateSeverity,
	parseTimestamp("Jan _2 15:04:05"), // Oct  5 12:05:15
	nginxFixTimestamp,                 // adds the years.
	discardSpace,
	parseHostname, // hostname
	discardSpace,
	parseAppname,    // nginx:
	nginxFixAppName, // nginx: -> nginx
	discardSpace,
	parseData, // [request remote_addr="192.168.1.255" status="200"]
}

// Format: <187>Oct 13 12:31:40 hostname nginx: 2015/10/13 01:31:40 [error] 1187#1187: *46 open() "/usr/share/nginx/html/test" failed (2: No such file or directory), client: 192.168.1.255, server: localhost, request: "GET /test HTTP/1.1", host: "192.168.1.254".
var nginxErrorFormat = format{
	parsePriority, // <187>
	calculateFacility,
	calculateSeverity,
	parseTimestamp("Jan _2 15:04:05"), // Oct 13 12:31:40
	nginxFixTimestamp,                 // adds the years.
	discardSpace,
	parseHostname, // hostname
	discardSpace,
	parseAppname,    // nginx:
	nginxFixAppName, // nginx: -> nginx
	discardSpace,
	discard(19), // Timestamp is provided again (2015/10/13 01:31:40).
	discardSpace,
	discardByte('['),
	discardUntil(']'), // Severity is given again ([Error]).
	discardSpace,
	parseNginxMsg, // 1187#1187: *46 open() "/usr/share/nginx/html/test" failed (2: No such file or directory),
	discardSpace,
	parseNginxData, // client: 192.168.1.255, server: localhost, request: "GET /test HTTP/1.1", host: "192.168.1.254"
}
