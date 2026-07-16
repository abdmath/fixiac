package context_test

import (
	contextPkg "context"
	"path/filepath"
	"testing"

	"github.com/abdma/fixiac/internal/context"
)

func TestAnalyzer_Analyze(t *testing.T) {
	targetDir, err := filepath.Abs("../../testdata")
	if err != nil {
		t.Fatalf("failed to get absolute path to testdata: %v", err)
	}

	analyzer := context.NewAnalyzer()
	ctx, err := analyzer.Analyze(contextPkg.Background(), targetDir)
	if err != nil {
		t.Fatalf("Analyze returned unexpected error: %v", err)
	}

	if ctx == nil {
		t.Fatal("expected non-nil CodebaseContext")
	}

	if len(ctx.FileContents) == 0 {
		t.Errorf("expected at least one file in FileContents, got 0")
	}

	foundS3File := false
	for path, content := range ctx.FileContents {
		if filepath.Base(path) == "s3_bucket.tf" {
			foundS3File = true
			if len(content) == 0 {
				t.Errorf("expected non-empty file content for s3_bucket.tf")
			}
		}
	}

	if !foundS3File {
		t.Errorf("did not find s3_bucket.tf in FileContents")
	}
}
