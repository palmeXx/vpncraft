//go:build !windows

package capture

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

func runFilter(t *testing.T, link LinkType, frame []byte) bool {
	t.Helper()
	raw, err := filterProgram(link, 6112)
	if err != nil {
		t.Fatalf("filterProgram() error = %v", err)
	}
	prog, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("Disassemble() could not decode all instructions")
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatalf("NewVM() error = %v", err)
	}
	n, err := vm.Run(frame)
	if err != nil {
		t.Fatalf("vm.Run() error = %v", err)
	}
	return n > 0
}

func TestFilterProgram(t *testing.T) {
	match := buildIPv4UDP("255.255.255.255", 50000, 6112, []byte{0xF7})
	srcMatch := buildIPv4UDP("192.0.2.2", 6112, 50000, []byte{0xF7})
	other := buildIPv4UDP("192.0.2.2", 53, 53, []byte{0})

	tcp := buildIPv4UDP("192.0.2.2", 6112, 6112, nil)
	tcp[9] = 6

	frag := buildIPv4UDP("192.0.2.2", 6112, 6112, nil)
	binary.BigEndian.PutUint16(frag[6:], 0x0010)

	withOptions := buildIPv4UDP("192.0.2.2", 1, 6112, nil)
	withOptions = append(withOptions[:20], append([]byte{1, 1, 1, 0}, withOptions[20:]...)...)
	withOptions[0] = 0x46

	null := binary.LittleEndian.AppendUint32(nil, afInet)

	tests := []struct {
		name  string
		link  LinkType
		frame []byte
		want  bool
	}{
		{"raw dst port", LinkRaw, match, true},
		{"raw src port", LinkRaw, srcMatch, true},
		{"raw other port", LinkRaw, other, false},
		{"raw tcp", LinkRaw, tcp, false},
		{"raw fragment", LinkRaw, frag, false},
		{"raw ip options", LinkRaw, withOptions, true},
		{"null", LinkNull, append(null, match...), true},
		{"null other port", LinkNull, append(null, other...), false},
		{"ethernet", LinkEthernet, ethernet(etherTypeIPv4, false, match), true},
		{"ethernet arp", LinkEthernet, ethernet(0x0806, false, match), false},
		{"ethernet other port", LinkEthernet, ethernet(etherTypeIPv4, false, other), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runFilter(t, tt.link, tt.frame); got != tt.want {
				t.Errorf("filter accepted = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterProgramUnsupportedLink(t *testing.T) {
	if _, err := filterProgram(LinkType(999), 6112); err == nil {
		t.Error("filterProgram() error = nil, want error")
	}
}
