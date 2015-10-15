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

	priorityByte, err := buf.ReadSlice(priorityEnd)
	if err == io.EOF {
		return newFormatError("priority not closed")
	} else if err != nil {
		return err
	} else if len(priorityByte) > maxPriorityLength+1 { // closing tag is included.
		return newFormatError("priority too long")
	}
	priorityByte = priorityByte[:len(priorityByte)-1]

	priority, err := strconv.Atoi(string(priorityByte))
	if err != nil {
		return newFormatError("priority not a number: " + err.Error())
	}

	msg.Priority = Priority(priority)
	return nil
}

func parseVersion(buf *buffer, msg *Message) error {
	versionBytes, err := buf.Peek(maxVersionLength)
	if err != nil {
		return err
	}

	// Version can be between 0 and 2 digits long.
	if versionBytes[0] == spaceByte {
		return nil
	} else if versionBytes[1] == spaceByte {
		versionBytes = versionBytes[:1]
	}

	version, err := strconv.ParseUint(string(versionBytes), 10, 0)
	if err != nil {
		return newFormatError("version not a number: " + err.Error())
	}

	if n := buf.Discard(len(versionBytes)); n != len(versionBytes) {
		return io.EOF
	}

	msg.Version = uint(version)
	return nil
}

func parseTimestamp(formats ...string) parseFunc {
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
		return newFormatError("timestamp is not following an accepted format")
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
				return newFormatError("expected byte '" + string(dataEnd) +
					"' or '" + string(spaceByte) + "', but got '" + string(c) + "'")
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
			return newFormatError("expected byte '" + string(spaceByte) +
				"' or '" + string(dataEnd) + "', but got '" + string(c) + "'")
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
		return "", newFormatError("data param name too long")
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
	messageBytes = bytes.TrimPrefix(messageBytes, bom)
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

// DiscardUntil discard all bytes until the given byte is found.
//
// Note: the discarded bytes include the given byte.
func discardUntil(c byte) parseFunc {
	return func(buf *buffer, msg *Message) error {
		_, err := buf.ReadSlice(c)
		return err
	}
}

func discardSpace(buf *buffer, msg *Message) error {
	return checkByte(buf, spaceByte)
}

func parseSingleValue(buf *buffer, name string, allowNilValue bool, maxLength int) (string, error) {
	if allowNilValue && nextIsNilValue(buf) {
		return "", nil
	}

	value, err := buf.ReadSlice(spaceByte)
	if err != nil && err != io.EOF {
		return "", err
	} else if len(value) > maxLength+1 { // space is included.
		return "", newFormatError(name + " too long")
	}

	buf.UnreadByte()
	return string(value[:len(value)-1]), nil
}

func checkByte(buf *buffer, expected byte) error {
	c, err := buf.ReadByte()
	if err != nil {
		return err
	} else if c != expected {
		return newFormatError("expected byte '" + string(expected) +
			"', but got '" + string(c) + "'")
	}
	return nil
}

// NextIsNilValue checks if the next byte is a nil value byte. If this function
// return true, the byte will be read. If it returns false it doesn't read the
// byte.
// If the reader returns an error this function returns false, with the
// expectation that the next read will return the same error.
func nextIsNilValue(buf *buffer) bool {
	if c, err := buf.ReadByte(); err != nil || c != nilValueByte {
		buf.UnreadByte()
		return false
	}
	return true
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

		// todo: optizime this. Possible lines:
		// `key: value,`
		// `key: value`
		// ` key: value`
		// `key: "value",`
		// `key: "value"`
		// ` key: "value"`
		keyValue := bytes.SplitN(bb, []byte{colonByte}, 2)
		key := bytes.TrimPrefix(keyValue[0], []byte{spaceByte})
		value := keyValue[1]
		value = bytes.TrimPrefix(value, []byte{spaceByte})
		value = bytes.TrimSuffix(value, []byte{commaByte})
		value = bytes.TrimPrefix(value, []byte{qouteByte})
		value = bytes.TrimSuffix(value, []byte{qouteByte})

		data[string(key)] = string(value)

		if err == io.EOF {
			break
		}
	}

	msg.Data = map[string]map[string]string{}
	msg.Data["data"] = data
	return nil
}
