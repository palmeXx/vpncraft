package wc3

import (
	"testing"
)

func TestIsW3GS(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    bool
	}{
		{"empty", nil, false},
		{"w3gs", []byte{0xF7, 0x2F}, true},
		{"other", []byte{0x01, 0x2F}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsW3GS(tt.payload); got != tt.want {
				t.Errorf("IsW3GS(%x) = %v, want %v", tt.payload, got, tt.want)
			}
		})
	}
}

func TestDescribe(t *testing.T) {
	// Synthetic GAMEINFO-like packet: header, 4 filler bytes, game name, map/settings.
	gameInfo := []byte{0xF7, 0x30, 0x1C, 0x00, 'P', 'X', '3', 'W'}
	gameInfo = append(gameInfo, "Test Game\x00"...)
	gameInfo = append(gameInfo, "Maps\\Test.w3x\x00"...)

	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{
			name:    "too short",
			payload: []byte{0xF7, 0x30},
			want:    "Payload too short to be a valid WC3 packet.",
		},
		{
			name:    "non w3gs",
			payload: []byte{0x01, 0x02, 0x03, 0x04},
			want:    "Non-WC3 Packet Payload (Header byte: 0x01)",
		},
		{
			name:    "game info",
			payload: gameInfo,
			want: "Host IP Address: 192.0.2.10\n" +
				"Packet ID: 0x30 | Declared Length: 28 bytes\n" +
				"Game Name: 'Test Game'\n" +
				"Map / Settings: 'Maps\\Test.w3x'",
		},
		{
			name:    "game info without terminators",
			payload: []byte{0xF7, 0x31, 0x08, 0x00, 1, 2, 3, 4, 'a', 'b'},
			want: "Host IP Address: 192.0.2.10\n" +
				"Packet ID: 0x31 | Declared Length: 8 bytes",
		},
		{
			name:    "game info header only",
			payload: []byte{0xF7, 0x32, 0x04, 0x00},
			want: "Host IP Address: 192.0.2.10\n" +
				"Packet ID: 0x32 | Declared Length: 4 bytes",
		},
		{
			name:    "invalid utf8 in name is dropped",
			payload: []byte{0xF7, 0x33, 0x0C, 0x00, 0, 0, 0, 0, 'a', 0xFF, 'b', 0},
			want: "Host IP Address: 192.0.2.10\n" +
				"Packet ID: 0x33 | Declared Length: 12 bytes\n" +
				"Game Name: 'ab'",
		},
		{
			name:    "other packet renders ascii",
			payload: []byte{0xF7, 0x2F, 0x10, 0x00, 'P', 'X', '3', 'W', 0x1A},
			want: "Host IP Address: 192.0.2.10\n" +
				"Packet ID: 0x2F | Declared Length: 16 bytes\n" +
				"ASCII Stream: ./..PX3W.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Describe(tt.payload, "192.0.2.10"); got != tt.want {
				t.Errorf("Describe() =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func FuzzDescribe(f *testing.F) {
	f.Add([]byte{0xF7, 0x30, 0x00, 0x00, 0, 0, 0, 0, 'x', 0, 'y', 0})
	f.Add([]byte{0xF7})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_ = Describe(b, "192.0.2.10")
	})
}
