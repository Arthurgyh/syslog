// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

package syslog

const (
	multiplier  = 8
	maxFacility = 23
	maxSeverity = 7
	maxPriority = maxFacility*multiplier + maxSeverity
)

// Priority used to calculate facility and severity.
type Priority uint8

// CalculateFacility returns the facility.
//
// Note: it doesn't test if the facility is valid.
func (priority Priority) CalculateFacility() Facility {
	facility := priority / multiplier
	return Facility(facility)
}

// CalculateSeverity returns the severity.
//
// Note: it doesn't test if the severity is valid.
func (priority Priority) CalculateSeverity() Severity {
	severity := priority - ((priority / multiplier) * multiplier)
	return Severity(severity)
}

// IsValid checks if the priority is valid. That is between 0 and 191.
func (priority Priority) IsValid() bool {
	return priority <= maxPriority
}

// CalculatePriority takes a facility and severity level to calculate a
// priority level.
func CalculatePriority(facility Facility, severity Severity) Priority {
	priority := int(facility)*multiplier + int(severity)
	return Priority(priority)
}

// Facility level.
type Facility uint8

// IsValid checks if the facility is valid. That is between 0 and 23.
func (facility Facility) IsValid() bool {
	return facility <= maxFacility
}

// Available facility levels, taken from RFC 5424.
const (
	Kernel                 Facility = iota // Kernel messages.
	UserLevel                              // User-level messages.
	Mail                                   // Mail system.
	System                                 // System daemons.
	SecurityAuthorization                  // Security/authorization messages.
	Internal                               // Messages generated internally by syslogd.
	LinePrinter                            // Line printer subsystem.
	NetworkNews                            // Network news subsystem.
	UUCP                                   // UUCP subsystem.
	ClockDeamon                            // Clock daemon.
	SecurityAuthorization2                 // Security/authorization messages.
	FTPDeamon                              // FTP daemon.
	NTPSubsystem                           // NTP subsystem.
	LogAudit                               // Log audit.
	LogAlert                               // Log alert.
	ClockDeamon2                           // Clock daemon (note 2).
	Local0                                 // Local use 0  (local0).
	Local1                                 // Local use 1  (local1).
	Local2                                 // Local use 2  (local2).
	Local3                                 // Local use 3  (local3).
	Local4                                 // Local use 4  (local4).
	Local5                                 // Local use 5  (local5).
	Local6                                 // Local use 6  (local6).
	Local7                                 // Local use 7  (local7).
)

// Severity level indicator.
type Severity uint8

// IsValid checks if the severity is valid. That is between 0 and 7.
func (severity Severity) IsValid() bool {
	return severity <= maxSeverity
}

// Available severity levels, taken from RFC 5424.
const (
	Emergency     Severity = iota // Emergency: system is unusable.
	Alert                         // Alert: action must be taken immediately.
	Critical                      // Critical: critical conditions.
	Error                         // Error: error conditions.
	Warning                       // Warning: warning conditions.
	Notice                        // Notice: normal but significant condition.
	Informational                 // Informational: informational messages.
	Debug                         // Debug: debug-level messages.
)
