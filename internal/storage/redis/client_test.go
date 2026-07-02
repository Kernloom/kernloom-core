// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package redis

import (
	"bufio"
	"bytes"
	"errors"
	"testing"
)

func TestEncodeCommand(t *testing.T) {
	got := encodeCommand("SET", "kernloom:job:1", "pending")
	want := "*3\r\n$3\r\nSET\r\n$14\r\nkernloom:job:1\r\n$7\r\npending\r\n"
	if string(got) != want {
		t.Fatalf("unexpected command encoding\nwant: %q\n got: %q", want, got)
	}
}

func TestReadValueParsesBulkString(t *testing.T) {
	value, err := readValue(bufio.NewReader(bytes.NewBufferString("$7\r\njob-123\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if value.String != "job-123" {
		t.Fatalf("unexpected value %#v", value)
	}
}

func TestReadValueParsesNilBulkString(t *testing.T) {
	_, err := readValue(bufio.NewReader(bytes.NewBufferString("$-1\r\n")))
	if !errors.Is(err, ErrNil) {
		t.Fatalf("expected ErrNil, got %v", err)
	}
}
