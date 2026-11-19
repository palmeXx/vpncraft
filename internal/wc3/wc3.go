// Package wc3 decodes Warcraft III LAN (W3GS) UDP payloads.
package wc3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	// Port is the UDP/TCP port Warcraft III uses for LAN games.
	Port = 6112
	// HeaderByte is the W3GS protocol identifier, first byte of every packet.
	HeaderByte = 0xF7

	// minHeaderLen is header byte + packet ID + uint16 LE length.
	minHeaderLen = 4
	// gameNameOffset skips the 4-byte header and a 4-byte game/version field.
	gameNameOffset = 8
)

// IsW3GS reports whether payload starts with the W3GS header byte.
func IsW3GS(payload []byte) bool {
	return len(payload) > 0 && payload[0] == HeaderByte
}

// Describe renders a W3GS payload as multi-line, human-readable text.
func Describe(payload []byte, srcIP string) string {
	if len(payload) < minHeaderLen {
		return "Payload too short to be a valid WC3 packet."
	}

	header := payload[0]
	cmdID := payload[1]
	pktLen := binary.LittleEndian.Uint16(payload[2:4])

	if header != HeaderByte {
		return fmt.Sprintf("Non-WC3 Packet Payload (Header byte: 0x%02X)", header)
	}

	lines := []string{
		"Host IP Address: " + srcIP,
		fmt.Sprintf("Packet ID: 0x%02X | Declared Length: %d bytes", cmdID, pktLen),
	}

	switch cmdID {
	case 0x30, 0x31, 0x32, 0x33:
		offset := gameNameOffset
		if name, next, ok := cString(payload, offset); ok {
			lines = append(lines, fmt.Sprintf("Game Name: '%s'", name))
			offset = next
		}
		if mapName, _, ok := cString(payload, offset); ok {
			lines = append(lines, fmt.Sprintf("Map / Settings: '%s'", mapName))
		}
	default:
		lines = append(lines, "ASCII Stream: "+printable(payload))
	}

	return strings.Join(lines, "\n")
}

// cString reads a NUL-terminated string starting at offset. Invalid UTF-8 is dropped.
func cString(b []byte, offset int) (s string, next int, ok bool) {
	if offset >= len(b) {
		return "", offset, false
	}
	end := bytes.IndexByte(b[offset:], 0)
	if end < 0 {
		return "", offset, false
	}
	return strings.ToValidUTF8(string(b[offset:offset+end]), ""), offset + end + 1, true
}

func printable(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 32 && c <= 126 {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}
