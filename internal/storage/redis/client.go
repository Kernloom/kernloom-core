// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package redis

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var ErrNil = errors.New("redis nil")

type Client struct {
	Addr    string
	Timeout time.Duration
}

type Value struct {
	Kind   byte
	String string
	Int    int64
	Array  []Value
	Nil    bool
}

func (c Client) Do(ctx context.Context, args ...string) (Value, error) {
	if len(args) == 0 {
		return Value{}, fmt.Errorf("redis command requires at least one argument")
	}
	addr := c.Addr
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Value{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write(encodeCommand(args...)); err != nil {
		return Value{}, err
	}
	return readValue(bufio.NewReader(conn))
}

func encodeCommand(args ...string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(arg), arg)
	}
	return b.Bytes()
}

func readValue(r *bufio.Reader) (Value, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return Value{}, err
	}
	switch prefix {
	case '+':
		line, err := readLine(r)
		return Value{Kind: '+', String: line}, err
	case '-':
		line, err := readLine(r)
		if err != nil {
			return Value{}, err
		}
		return Value{}, fmt.Errorf("redis error: %s", line)
	case ':':
		line, err := readLine(r)
		if err != nil {
			return Value{}, err
		}
		value, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: ':', Int: value}, nil
	case '$':
		return readBulkString(r)
	case '*':
		return readArray(r)
	default:
		return Value{}, fmt.Errorf("unsupported redis response prefix %q", prefix)
	}
}

func readBulkString(r *bufio.Reader) (Value, error) {
	line, err := readLine(r)
	if err != nil {
		return Value{}, err
	}
	length, err := strconv.Atoi(line)
	if err != nil {
		return Value{}, err
	}
	if length == -1 {
		return Value{Kind: '$', Nil: true}, ErrNil
	}
	buf := make([]byte, length+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Value{}, err
	}
	if !bytes.HasSuffix(buf, []byte("\r\n")) {
		return Value{}, fmt.Errorf("invalid redis bulk string terminator")
	}
	return Value{Kind: '$', String: string(buf[:length])}, nil
}

func readArray(r *bufio.Reader) (Value, error) {
	line, err := readLine(r)
	if err != nil {
		return Value{}, err
	}
	length, err := strconv.Atoi(line)
	if err != nil {
		return Value{}, err
	}
	if length == -1 {
		return Value{Kind: '*', Nil: true}, ErrNil
	}
	values := make([]Value, 0, length)
	for range length {
		value, err := readValue(r)
		if err != nil && !errors.Is(err, ErrNil) {
			return Value{}, err
		}
		values = append(values, value)
	}
	return Value{Kind: '*', Array: values}, nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}
