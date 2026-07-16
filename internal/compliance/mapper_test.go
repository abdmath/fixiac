package compliance_test

import (
	"strings"
	"testing"

	"github.com/abdma/fixiac/internal/compliance"
)

func TestMapper_MapFinding(t *testing.T) {
	mapper := compliance.NewMapper()
	if mapper == nil {
		t.Fatal("expected non-nil Mapper")
	}

	controls := mapper.MapFinding("CKV_AWS_18")
	if len(controls) == 0 {
		t.Errorf("expected compliance controls for CKV_AWS_18, got 0")
	}

	foundSOC2 := false
	for _, ctrl := range controls {
		if strings.EqualFold(ctrl.Framework, "soc2") {
			foundSOC2 = true
			break
		}
	}

	if !foundSOC2 {
		t.Errorf("expected SOC2 mapping for CKV_AWS_18")
	}
}
