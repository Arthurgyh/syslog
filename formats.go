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

	// Nginx is the format to parse Nginx syslog messages. To allow the
	// Message.Data to be filled the following logformat is required to be used:
	//
	//	log_format syslog '[request body_bytes_sent="$body_bytes_sent" '
	//		'connection="$connection" '
	//		'connection_requests="$connection_requests" '
	//		'http_referer="$http_referer" '
	//		'http_user_agent="$http_user_agent" '
	//		'http_x_forwarded_for="$http_x_forwarded_for" '
	//		'msec="$msec" '
	//		'remote_addr="$remote_addr" '
	//		'remote_user="$remote_user" '
	//		'request_length="$request_length" '
	//		'request_time="$request_time" '
	//		'status="$status"]';
	//
	// Using this log_format allows the Message.Data["Request"] to be filled with
	// the data from Nginx.
	Nginx = nginxFormat
)

var rfc5424Format = format{
	parsePriority,
	calculateFacility,
	calculateSeverity,
	parseVersion,
	parseSpace,
	parseTimestamp(time.RFC3339, time.RFC3339Nano),
	parseSpace,
	parseHostname,
	parseSpace,
	parseAppname,
	parseSpace,
	parseProcessID,
	parseSpace,
	parseMessageID,
	parseSpace,
	parseData,
	optional(2, parseSpace, parseMsg),
}

var nginxFormat = format{
	parsePriority,
	calculateFacility,
	calculateSeverity,
	parseTimestamp("Jan _2 15:04:05"),
	nginxFixTimestamp,
	parseSpace,
	parseHostname,
	parseSpace,
	parseAppname,
	nginxFixAppName,
	parseSpace,
	parseData,
}
