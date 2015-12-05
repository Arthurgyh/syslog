// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed under the MIT license that can be found in the LICENSE file.

package syslog

import (
	"bytes"
	"io"
	"strconv"
	"time"
)

const (
	maxPriorityLength  = 3
	maxVersionLength   = 2
	maxHostnameLength  = 255
	maxAppNameLength   = 48
	maxProcessIDLength = 128
	maxMessageIDLength = 32
	maxDataIDLength    = 32
	maxDataParamLength = 32

	spaceByte     byte = ' '
	nilValueByte  byte = '-'
	equalByte     byte = '='
	qouteByte     byte = '"'
	commaByte     byte = ','
	colonByte     byte = ':'
	priorityStart byte = '<'
	priorityEnd   byte = '>'
	dataStart     byte = '['
	dataEnd       byte = ']'

	nilValue = string(nilValueByte)
)

// Threat as constant.
var bom = []byte{239, 187, 191}

type parseFunc func(*buffer, *Message) error

func parsePriority(buf *buffer, msg *Message) error {
	if err := checkByte(buf, priorityStart); err != nil {
		return err
	}

	startPos := buf.Pos()
	priorityBytes, err := buf.ReadSlice(priorityEnd)
	if err == io.EOF {
		pos := startPos + maxPriorityLength
		if pos > buf.Pos() {
			pos = buf.Pos()
		}
		return newFormatError(pos, "priority not closed")
	} else if err != nil {
		return err
	} else if len(priorityBytes) > maxPriorityLength+1 { // Closing tag included.
		return newFormatError(startPos+maxPriorityLength, "priority too long")
	}

	priorityBytes = priorityBytes[:len(priorityBytes)-1]
	if len(priorityBytes) == 0 {
		return newFormatError(startPos, "priority can't be empty")
	}

	priority, err := strconv.Atoi(string(priorityBytes))
	if err != nil {
		return newFormatError(startPos, "priority not a number: "+
			string(priorityBytes))
	}

	msg.Priority = Priority(priority)
	return nil
}

func parseVersion(buf *buffer, msg *Message) error {
	versionBytes, err := buf.Peek(maxVersionLength)
	if err != nil && err != io.EOF {
		return err
	}
	l := len(versionBytes)

	// Version can be between 0 and 2 digits long.
	if l == 0 || (l >= 1 && versionBytes[0] == spaceByte) {
		return nil
	} else if l == 2 && versionBytes[1] == spaceByte {
		versionBytes = versionBytes[:1]
		l = len(versionBytes)
	}

	version, err := strconv.ParseUint(string(versionBytes), 10, 0)
	if err != nil {
		return newFormatError(buf.Pos(), "version not a number: "+
			string(versionBytes))
	}

	if n := buf.Discard(l); n != l {
		return io.EOF
	}

	msg.Version = uint(version)
	return nil
}

func parseTimestamp(formats ...string) parseFunc {
	if len(formats) == 0 {
		panic("syslog: no formats supplied to parseTimestamp")
	}

	return func(buf *buffer, msg *Message) error {
		if nextIsNilValue(buf) {
			return nil
		}

		for _, format := range formats {
			timestamp, err := parseTimestampf(buf, format)
			if err != nil {
				continue
			}
			msg.Timestamp = timestamp
			return nil
		}

		// todo: improve the error message, include the given formats.
		return newFormatError(buf.Pos(), "timestamp is not following an accepted format")
	}
}

func parseTimestampf(buf *buffer, format string) (time.Time, error) {
	timeBytes, err := buf.Peek(len(format))
	if err != nil {
		return time.Time{}, err
	}

	timestamp, err := time.ParseInLocation(format, string(timeBytes), time.Now().Location())
	if err != nil {
		return time.Time{}, err
	}

	if n := buf.Discard(len(format)); n != len(format) {
		return time.Time{}, io.EOF
	}
	return timestamp, err
}

func parseHostname(buf *buffer, msg *Message) error {
	hostname, err := parseSingleValue(buf, "hostname", true, maxHostnameLength)
	if err != nil {
		return err
	}

	msg.Hostname = hostname
	return nil
}

func parseAppname(buf *buffer, msg *Message) error {
	appname, err := parseSingleValue(buf, "appname", true, maxAppNameLength)
	if err != nil {
		return err
	}

	msg.Appname = appname
	return nil
}

func parseProcessID(buf *buffer, msg *Message) error {
	processID, err := parseSingleValue(buf, "processID", true, maxProcessIDLength)
	if err != nil {
		return err
	}

	msg.ProcessID = processID
	return nil
}

func parseMessageID(buf *buffer, msg *Message) error {
	messageID, err := parseSingleValue(buf, "messageID", true, maxMessageIDLength)
	if err != nil {
		return err
	}

	msg.MessageID = messageID
	return nil
}

func parseData(buf *buffer, msg *Message) error {
	if nextIsNilValue(buf) {
		return nil
	} else if err := checkByte(buf, dataStart); err != nil {
		return err
	}

	var data = map[string]map[string]string{}
	for {
		dataID, err := parseSingleValue(buf, "data-ID", false, maxDataIDLength)
		if err != nil {
			return err
		}
		buf.ReadByte() // read next space.

		data[dataID] = map[string]string{}
		for {
			paramName, err := parseParamName(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}

			paramValue, err := parseParamValue(buf)
			if err != nil {
				return err
			}

			if paramValue != nilValue {
				data[dataID][paramName] = paramValue
			}

			if c, err := buf.ReadByte(); err != nil {
				return err
			} else if c == dataEnd {
				break
			} else if c != spaceByte {
				return newFormatError(buf.Pos(), "expected byte '"+string(dataEnd)+
					"' or '"+string(spaceByte)+"', but got '"+string(c)+"'")
			}
		}

		if c, err := buf.ReadByte(); err != nil && err != io.EOF {
			return err
		} else if err == io.EOF {
			break
		} else if c == spaceByte {
			buf.UnreadByte()
			break
		} else if c != dataStart {
			return newFormatError(buf.Pos(), "expected byte '"+string(spaceByte)+
				"' or '"+string(dataEnd)+"', but got '"+string(c)+"'")
		}
	}

	msg.Data = data
	return nil
}

func parseParamName(buf *buffer) (string, error) {
	nameBytes, err := buf.ReadSlice(equalByte)
	if err != nil {
		return "", err
	}
	nameBytes = nameBytes[:len(nameBytes)-1]

	if len(nameBytes) > maxDataParamLength {
		return "", newFormatError(buf.Pos()-len(nameBytes),
			"data param name too long")
	}

	return string(nameBytes), nil
}

func parseParamValue(buf *buffer) (string, error) {
	if err := checkByte(buf, qouteByte); err != nil {
		return "", err
	}

	// todo: test with unescaped and escaped characters: '"', '\' and ']'.
	paramValue, err := buf.ReadSlice(qouteByte)
	if err != nil && err != io.EOF {
		return "", err
	}

	return string(paramValue[:len(paramValue)-1]), nil
}

// ParseMsg reads the remainding bytes and trims an options BOM.
func parseMsg(buf *buffer, msg *Message) error {
	messageBytes := buf.ReadAll()
	messageBytes = bytes.TrimSpace(messageBytes)
	messageBytes = bytes.TrimPrefix(messageBytes, bom)
	messageBytes = bytes.TrimSpace(messageBytes)
	msg.Message = string(messageBytes)
	return nil
}

// Discard discard the number of given bytes.
func discard(n int) parseFunc {
	return func(buf *buffer, msg *Message) error {
		if nn := buf.Discard(n); nn != n {
			return io.EOF
		}
		return nil
	}
}

// DiscardByte check if the next byte is the given byte and then discards it.
// It returns an error if the next byte is not the given byte.
func discardByte(c byte) parseFunc {
	return func(buf *buffer, msg *Message) error {
		return checkByte(buf, c)
	}
}

// DiscardUntil discard all bytes until the given byte is found. If the bytes is
// not found the remainder of the buffer will be discarded.
//
// Note: the discarded bytes include the given byte.
func discardUntil(c byte) parseFunc {
	return func(buf *buffer, msg *Message) error {
		_, err := buf.ReadSlice(c)
		return err
	}
}

// Shortcut for checkByte with a space.
func discardSpace(buf *buffer, msg *Message) error {
	return checkByte(buf, spaceByte)
}

func parseSingleValue(buf *buffer, name string, allowNilValue bool, maxLength int) (string, error) {
	if allowNilValue && nextIsNilValue(buf) {
		return "", nil
	}

	value, err := buf.ReadSlice(spaceByte)
	l := len(value)
	if (err != nil && err != io.EOF) || (err == io.EOF && l == 0) {
		return "", err
	}

	if err != io.EOF {
		// Space is included.
		maxLength++
	}
	if l > maxLength {
		return "", newFormatError(buf.Pos()-l+1, name+" too long")
	}

	// todo: this is really a temporary workaround because parseData uses this in
	// Data-ID. In case of no (empty) data it will be "[Data-ID]", so the value at
	// this point will be "Data-ID]", and we need to unread "]". But I'm not sure
	// this is the best solution.
	if b := value[l-1]; b == spaceByte || b == dataEnd {
		value = value[:l-1]
		buf.UnreadByte()
	}

	return string(value), nil
}

func checkByte(buf *buffer, expected byte) error {
	startPos := buf.Pos()
	c, err := buf.ReadByte()
	if err != nil {
		return err
	} else if c != expected {
		return newFormatError(startPos, "expected byte '"+string(expected)+
			"', but got '"+string(c)+"'")
	}
	return nil
}

// NextIsNilValue checks if the next byte is a nil value byte. If this function
// return true, the byte will be read. If it returns false it doesn't read the
// byte.
// If the reader returns an error this function returns false, with the
// expectation that the next read will return the same error.
func nextIsNilValue(buf *buffer) bool {
	b, err := buf.ReadByte()
	if err == nil && b == nilValueByte {
		return true
	}

	if err != io.EOF {
		buf.UnreadByte()
	}
	return false
}

func parseNginxMsg(buf *buffer, msg *Message) error {
	bytes, err := buf.ReadSlice(commaByte)
	if err != nil {
		return err
	}

	msg.Message = string(bytes[:len(bytes)-1])
	return nil
}

func parseNginxData(buf *buffer, msg *Message) error {
	var data = map[string]string{}
	for {
		bb, err := buf.ReadSlice(commaByte)
		if err != nil && err != io.EOF {
			return err
		}
		bb = bytes.TrimSuffix(bb, []byte{commaByte})

		keyValue := bytes.SplitN(bb, []byte{colonByte}, 2)
		if len(keyValue) != 2 {
			// todo: improve error message, be more clear about it.
			return newFormatError(buf.Pos()-len(keyValue),
				"Expected to encounter ':', but didn't find one")
		}

		key := bytes.TrimSpace(keyValue[0])
		value := bytes.TrimSpace(keyValue[1])

		qouteSlice := []byte{qouteByte}
		key = bytes.TrimPrefix(bytes.TrimSuffix(key, qouteSlice), qouteSlice)
		value = bytes.TrimPrefix(bytes.TrimSuffix(value, qouteSlice), qouteSlice)

		data[string(key)] = string(value)

		if err == io.EOF {
			break
		}
	}

	msg.Data = map[string]map[string]string{}
	msg.Data["data"] = data
	return nil
}
