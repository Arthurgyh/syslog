// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed under the MIT license that can be found in the LICENSE file.

package syslog

import "testing"

func TestPriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Priority Priority
		Facility Facility
		Severity Severity
	}{
		{0, Kernel, Emergency},
		{9, UserLevel, Alert},
		{185, Local7, Alert},
		{15, UserLevel, Debug},
		{96, NTP, Emergency},
		{103, NTP, Debug},
		{4, Kernel, Warning},
		{188, Local7, Warning},
		{191, Local7, Debug},
	}

	for _, test := range tests {
		if got := test.Priority.CalculateFacility(); got != test.Facility {
			t.Fatalf("Expected Priority(%d).CalculateFacility() to return %d, but got %d",
				test.Priority, test.Facility, got)
		}
		if got := test.Priority.CalculateSeverity(); got != test.Severity {
			t.Fatalf("Expected Priority(%d).CalculateSeverity() to return %d, but got %d",
				test.Priority, test.Severity, got)
		}
		if got := CalculatePriority(test.Facility, test.Severity); got != test.Priority {
			t.Fatalf("Expected CalculatePriority(%d, %d) to return %d, but got %d",
				test.Facility, test.Severity, test.Priority, got)
		}
	}
}

func TestPriorityIsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Priority      Priority
		PriorityValid bool
		Facility      Facility
		FacilityValid bool
		Severity      Severity
		SeverityValid bool
	}{
		{0, true, 0, true, 0, true},
		{9, true, 1, true, 1, true},
		{185, true, 23, true, 1, true},
		{15, true, 1, true, 7, true},
		{96, true, 12, true, 0, true},
		{103, true, 12, true, 7, true},
		{4, true, 0, true, 4, true},
		{188, true, 23, true, 4, true},
		{191, true, 23, true, 7, true},

		{192, false, 24, false, 0, true},
		{199, false, 24, false, 7, true},
		{8, true, 0, true, 8, false},
	}

	for _, test := range tests {
		if got := test.Priority.IsValid(); got != test.PriorityValid {
			t.Fatalf("Expected Priority(%d).IsValid() to return %t, but got %t",
				test.Priority, test.PriorityValid, got)
		}
		if got := test.Facility.IsValid(); got != test.FacilityValid {
			t.Fatalf("Expected Facility(%d).IsValid() to return %t, but got %t",
				test.Facility, test.FacilityValid, got)
		}
		if got := test.Severity.IsValid(); got != test.SeverityValid {
			t.Fatalf("Expected Severity(%d).IsValid() to return %t, but got %t",
				test.Severity, test.SeverityValid, got)
		}
	}
}

func TestFacilityString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Facility Facility
		Expected string
	}{
		{Kernel, "Kernel"},
		{UserLevel, "User-Level"},
		{Mail, "Mail"},
		{System, "System"},
		{SecurityAuthorization, "Security/authorization"},
		{Internal, "Internal"},
		{LinePrinter, "Line printer"},
		{NetworkNews, "Network news"},
		{UUCP, "UUCP"},
		{ClockDeamon, "Clock deamon"},
		{SecurityAuthorization, "Security/authorization"},
		{FTPDeamon, "FTP deamon"},
		{NTP, "NTP"},
		{LogAudit, "Log audit"},
		{LogAlert, "Log alert"},
		{ClockDeamon2, "Clock deamon2"},
		{Local0, "Local 0"},
		{Local1, "Local 1"},
		{Local2, "Local 2"},
		{Local3, "Local 3"},
		{Local4, "Local 4"},
		{Local5, "Local 5"},
		{Local6, "Local 6"},
		{Local7, "Local 7"},
		{Facility(24), "Invalid"},
	}

	for _, test := range tests {
		got := test.Facility.String()
		if got != test.Expected {
			t.Fatalf("Expected %#v.String() to return %s, but got %s",
				test.Facility, test.Expected, got)
		}
	}
}

func TestSeverityString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Severity Severity
		Expected string
	}{
		{Emergency, "Emergency"},
		{Alert, "Alert"},
		{Critical, "Critical"},
		{Error, "Error"},
		{Warning, "Warning"},
		{Notice, "Notice"},
		{Informational, "Informational"},
		{Debug, "Debug"},
		{Severity(9), "Invalid"},
	}

	for _, test := range tests {
		got := test.Severity.String()
		if got != test.Expected {
			t.Fatalf("Expected %#v.String() to return %s, but got %s",
				test.Severity, test.Expected, got)
		}
	}
}
