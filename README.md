# Syslog

[![GoDoc](https://godoc.org/github.com/Thomasdezeeuw/syslog?status.svg)](https://godoc.org/github.com/Thomasdezeeuw/syslog)
[![Build Status](https://travis-ci.org/Thomasdezeeuw/syslog.png?branch=master)](https://travis-ci.org/Thomasdezeeuw/syslog)

Syslog is a package to parse syslog messages. It currently has formats for
RFC5424 and Nginx access and error logs.

## Warning

This package is very much in the alpha stage. This API might change, but more
importantly the parsing formats might not be 100% correct and might too strict.

## Installation

Run the following line to install.

```bash
$ go get github.com/Thomasdezeeuw/syslog
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/Thomasdezeeuw/syslog"
)

const msg = `<191>10 2015-09-30T23:10:11+02:00 hostname appname procid msgid [data name="value"] message`

func main() {
	msg, err := syslog.ParseMessage([]byte(msg), syslog.RFC5424)
	if err != nil {
		panic(err)
	}

	fmt.Println(msg)
}
```

## License

Licensed under the MIT license, copyright (C) Thomas de Zeeuw.
