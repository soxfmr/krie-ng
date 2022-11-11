//go:generate go run github.com/mailru/easyjson/easyjson -no_std_marshalers $GOFILE

package events

import (
	"bytes"
	"fmt"
	manager "github.com/DataDog/ebpf-manager"
)

func addUmhProbes(all *[]*manager.Probe) {
	*all = append(*all, []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/call_usermodehelper_exec",
				EBPFFuncName: "kprobe_call_usermodehelper_exec",
			},
		},
	}...)
}

func addUmhRoutes(all *[]manager.TailCallRoute) {}

func addUmhSelectors(all *[]manager.ProbesSelector) {
	*all = append(*all,
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/call_usermodehelper_exec", EBPFFuncName: "kprobe_call_usermodehelper_exec"}},
	)
}

type CallUserModeHelperEvent struct {
	Path string `json:"path"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *CallUserModeHelperEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 256 {
		return 0, fmt.Errorf("while parsing CallUserModeHelperEvent, got len %d, needed %d: %w", len(data), 4, ErrNotEnoughData)
	}
	rawBytePath, _, _ := bytes.Cut(data, []byte{0})
	e.Path = string(rawBytePath)
	return 4096, nil
}

// CallUserModeHelperEventSerializer is used to serialize CallUserModeHelperEvent
// easyjson:json
type CallUserModeHelperEventSerializer struct {
	*CallUserModeHelperEvent
}

// NewCallUserModeHelperEventSerializer returns a new instance of CallUserModeHelperEventSerializer
func NewCallUserModeHelperEventSerializer(e *CallUserModeHelperEvent) *CallUserModeHelperEventSerializer {
	return &CallUserModeHelperEventSerializer{
		CallUserModeHelperEvent: e,
	}
}
