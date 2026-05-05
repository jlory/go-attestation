package internal

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUntrustedParseEventType(t *testing.T) {
	tests := []struct {
		name    string
		et      uint32
		wantErr bool
	}{
		// Valid BIOS event range [0x0, 0x12]
		{name: "min BIOS event", et: 0x0, wantErr: false},
		{name: "mid BIOS event", et: 0x6, wantErr: false},
		{name: "max BIOS event", et: 0x12, wantErr: false},

		// Valid EFI event range [0x80000000, 0x800000FF]
		{name: "min EFI event", et: 0x80000000, wantErr: false},
		{name: "mid EFI event", et: 0x80000001, wantErr: false},
		{name: "max registered EFI event", et: 0x800000e0, wantErr: false},

		// Gap between BIOS and EFI ranges — must be rejected
		{name: "just above BIOS max", et: 0x13, wantErr: true},
		{name: "midpoint gap", et: 0x40000000, wantErr: true},
		{name: "just below EFI min", et: 0x7FFFFFFF, wantErr: true},

		// Above EFI range — must be rejected
		{name: "just above EFI max", et: 0x80000100, wantErr: true},
		{name: "far above EFI max", et: 0xFFFFFFFF, wantErr: true},

		// In-range but not in the known event map — must be rejected.
		// Note: every BIOS value [0x0, 0x12] is registered, so only gaps in the EFI
		// range can be used to test this path.
		{name: "unknown EFI type in valid range", et: 0x8000000A, wantErr: true},
		{name: "unknown EFI type near max", et: 0x800000FF, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UntrustedParseEventType(tc.et)
			if (err != nil) != tc.wantErr {
				t.Errorf("UntrustedParseEventType(%#x) error = %v, wantErr = %v", tc.et, err, tc.wantErr)
			}
		})
	}
}

func TestParseUEFIVariableData(t *testing.T) {
	data := []byte{0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0xd, 0x0, 0xe0, 0x98,
		0x3, 0x2b, 0x8c, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x53, 0x0, 0x65, 0x0, 0x63, 0x0, 0x75, 0x0, 0x72, 0x0,
		0x65, 0x0, 0x42, 0x0, 0x6f, 0x0, 0x6f, 0x0, 0x74, 0x0, 0x1}
	want := UEFIVariableData{
		Header: UEFIVariableDataHeader{
			VariableName:       efiGUID{Data1: 0x8be4df61, Data2: 0x93ca, Data3: 0x11d2, Data4: [8]uint8{0xaa, 0xd, 0x0, 0xe0, 0x98, 0x3, 0x2b, 0x8c}},
			UnicodeNameLength:  0xa,
			VariableDataLength: 0x1,
		},
		UnicodeName:  []uint16{0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x42, 0x6f, 0x6f, 0x74},
		VariableData: []uint8{0x1},
	}

	got, err := ParseUEFIVariableData(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseEFIVariableData() failed: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ParseUEFIVariableData() mismatch (-want +got):\n%s", diff)
	}
}
