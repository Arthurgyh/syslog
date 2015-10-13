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

	// Nginx is the format to parse Nginx syslog access messages. To allow the
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
	// the data from Nginx. Using the above we can acces the status using
	// Message.Data["Request"]["status"].
	NginxAccess = nginxAccessFormat
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

var nginxAccessFormat = format{
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
