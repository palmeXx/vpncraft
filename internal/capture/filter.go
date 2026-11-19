//go:build !windows

package capture

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// filterProgram builds a classic BPF program equivalent to
// "ip and udp and not ip[6:2] & 0x1fff != 0 and udp port <port>".
// It is evaluated in-kernel so only matching packets reach user space.
func filterProgram(link LinkType, port uint16) ([]bpf.RawInstruction, error) {
	var ipOff uint32
	var prog []bpf.Instruction

	switch link {
	case LinkRaw:
	case LinkNull, LinkLoop:
		ipOff = 4
	case LinkEthernet:
		// No VLAN support in-kernel; tagged frames are dropped by the filter.
		ipOff = 14
		prog = append(prog,
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIPv4, SkipFalse: 0xff}, // patched below
		)
	default:
		return nil, fmt.Errorf("unsupported link type %d", link)
	}

	prog = append(prog,
		// IPv4 version nibble.
		bpf.LoadAbsolute{Off: ipOff, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipFalse: 0xff},
		// Protocol == UDP.
		bpf.LoadAbsolute{Off: ipOff + 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoUDP, SkipFalse: 0xff},
		// Fragment offset == 0.
		bpf.LoadAbsolute{Off: ipOff + 6, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 0xff},
		// X = IP header length.
		bpf.LoadMemShift{Off: ipOff},
		// Source or destination port.
		bpf.LoadIndirect{Off: ipOff, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipTrue: 2},
		bpf.LoadIndirect{Off: ipOff + 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipFalse: 1},
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0},
	)

	// Resolve 0xff placeholders to "jump to final reject".
	reject := len(prog) - 1
	for i, ins := range prog {
		j, ok := ins.(bpf.JumpIf)
		if !ok {
			continue
		}
		if j.SkipFalse == 0xff {
			j.SkipFalse = uint8(reject - i - 1) //nolint:gosec // program is far shorter than 256 instructions
		}
		if j.SkipTrue == 0xff {
			j.SkipTrue = uint8(reject - i - 1) //nolint:gosec // see above
		}
		prog[i] = j
	}

	return bpf.Assemble(prog)
}
