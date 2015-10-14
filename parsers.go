// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

package syslog

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
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

type parseFunc func(*bufio.Reader, *Message) error

func parsePriority(b *bufio.Reader, msg *Message) error {
	if err := checkByte(b, priorityStart); err != nil {
		return err
	}

	priorityByte, err := b.ReadSlice(priorityEnd)
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

func parseVersion(b *bufio.Reader, msg *Message) error {
	versionBytes, err := b.Peek(maxVersionLength)
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

	if _, err := b.Discard(len(versionBytes)); err != nil {
		return err
	}

	msg.Version = uint(version)
	return nil
}

func parseTimestamp(formats ...string) parseFunc {
	return func(b *bufio.Reader, msg *Message) error {
		if nextIsNilValue(b) {
			return nil
		}

		for _, format := range formats {
			timestamp, err := parseTimestampf(b, format)
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

func parseTimestampf(b *bufio.Reader, format string) (time.Time, error) {
	timeBytes, err := b.Peek(len(format))
	if err != nil {
		return time.Time{}, err
	}

	timestamp, err := time.ParseInLocation(format, string(timeBytes), time.Now().Location())
	if err != nil {
		return time.Time{}, err
	}

	_, err = b.Discard(len(format))
	return timestamp, err
}

func parseHostname(b *bufio.Reader, msg *Message) error {
	hostname, err := parseSingleValue(b, "hostname", true, maxHostnameLength)
	if err != nil {
		return err
	}

	msg.Hostname = hostname
	return nil
}

func parseAppname(b *bufio.Reader, msg *Message) error {
	appname, err := parseSingleValue(b, "appname", true, maxAppNameLength)
	if err != nil {
		return err
	}

	msg.Appname = appname
	return nil
}

func parseProcessID(b *bufio.Reader, msg *Message) error {
	processID, err := parseSingleValue(b, "processID", true, maxProcessIDLength)
	if err != nil {
		return err
	}

	msg.ProcessID = processID
	return nil
}

func parseMessageID(b *bufio.Reader, msg *Message) error {
	messageID, err := parseSingleValue(b, "messageID", true, maxMessageIDLength)
	if err != nil {
		return err
	}

	msg.MessageID = messageID
	return nil
}

func parseData(b *bufio.Reader, msg *Message) error {
	if nextIsNilValue(b) {
		return nil
	} else if err := checkByte(b, dataStart); err != nil {
		return err
	}

	var data = map[string]map[string]string{}
	for {
		dataID, err := parseSingleValue(b, "data-ID", false, maxDataIDLength)
		if err != nil {
			return err
		}
		b.ReadByte() // read next space.

		data[dataID] = map[string]string{}
		for {
			paramName, err := parseParamName(b)
			if err != nil {
				return err
			}

			paramValue, err := parseParamValue(b)
			if err != nil {
				return err
			}

			if paramValue != nilValue {
				data[dataID][paramName] = paramValue
			}

			if c, err := b.ReadByte(); err != nil {
				return err
			} else if c == dataEnd {
				break
			} else if c != spaceByte {
				return newFormatError("expected byte '" + string(dataEnd) +
					"' or '" + string(spaceByte) + "', but got '" + string(c) + "'")
			}
		}

		if c, err := b.ReadByte(); err != nil && err != io.EOF {
			return err
		} else if err == io.EOF {
			break
		} else if c == spaceByte {
			b.UnreadByte()
			break
		} else if c != dataStart {
			return newFormatError("expected byte '" + string(spaceByte) +
				"' or '" + string(dataEnd) + "', but got '" + string(c) + "'")
		}
	}

	msg.Data = data
	return nil
}

func parseParamName(b *bufio.Reader) (string, error) {
	paramName, err := b.ReadString(equalByte)
	if err != nil && err != io.EOF {
		return "", err
	}
	paramName = paramName[:len(paramName)-1]

	if len(paramName) > maxDataParamLength {
		return "", newFormatError("data param name too long")
	}

	return paramName, nil
}

func parseParamValue(b *bufio.Reader) (string, error) {
	if err := checkByte(b, qouteByte); err != nil {
		return "", err
	}

	// todo: test with unescaped and escaped characters: '"', '\' and ']'.
	paramValue, err := b.ReadSlice(qouteByte)
	if err != nil && err != io.EOF {
		return "", err
	}

	return string(paramValue[:len(paramValue)-1]), nil
}

// ParseMsg reads the remainding bytes and trims an options BOM.
func parseMsg(b *bufio.Reader, msg *Message) error {
	messageBytes, err := ioutil.ReadAll(b)
	if err != nil {
		return err
	}
	messageBytes = bytes.TrimPrefix(messageBytes, bom)

	msg.Message = string(messageBytes)
	return nil
}

// Discard discard the number of given bytes.
func discard(n int) parseFunc {
	return func(b *bufio.Reader, msg *Message) error {
		_, err := b.Discard(n)
		return err
	}
}

// DiscardByte check if the next byte is the given byte and then discards it.
// It returns an error if the next byte is not the given byte.
func discardByte(c byte) parseFunc {
	return func(b *bufio.Reader, msg *Message) error {
		return checkByte(b, c)
	}
}

// DiscardUntil discard all bytes until the given byte is found.
//
// Note: the discarded bytes include the given byte.
func discardUntil(c byte) parseFunc {
	return func(b *bufio.Reader, msg *Message) error {
		_, err := b.ReadSlice(c)
		return err
	}
}

func discardSpace(b *bufio.Reader, msg *Message) error {
	return checkByte(b, spaceByte)
}

func parseSingleValue(b *bufio.Reader, name string, allowNilValue bool, maxLength int) (string, error) {
	if allowNilValue && nextIsNilValue(b) {
		return "", nil
	}

	value, err := b.ReadSlice(spaceByte)
	if err != nil && err != io.EOF {
		return "", err
	} else if len(value) > maxLength+1 { // space is included.
		return "", newFormatError(name + " too long")
	}

	return string(value[:len(value)-1]), b.UnreadByte()
}

func checkByte(b *bufio.Reader, expected byte) error {
	c, err := b.ReadByte()
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
func nextIsNilValue(b *bufio.Reader) bool {
	if c, err := b.ReadByte(); err != nil || c != nilValueByte {
		b.UnreadByte()
		return false
	}
	return true
}

func parseNginxMsg(b *bufio.Reader, msg *Message) error {
	bytes, err := b.ReadSlice(commaByte)
	if err != nil {
		return err
	}

	msg.Message = string(bytes[:len(bytes)-1])
	return nil
}

func parseNginxData(b *bufio.Reader, msg *Message) error {
	var data = map[string]string{}
	for {
		bb, err := b.ReadSlice(commaByte)
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
