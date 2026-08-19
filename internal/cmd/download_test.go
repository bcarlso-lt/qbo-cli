package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/voska/qbo-cli/internal/errfmt"
)

func TestSafeBaseNameStripsDirectories(t *testing.T) {
	got, err := safeBaseName("../../etc/passwd")
	if err != nil || got != "passwd" {
		t.Fatalf("got %q, %v; want %q", got, err, "passwd")
	}
}

func TestSafeBaseNameStripsBackslashDirectories(t *testing.T) {
	got, err := safeBaseName(`C:\tmp\receipt.pdf`)
	if err != nil || got != "receipt.pdf" {
		t.Fatalf("got %q, %v; want %q", got, err, "receipt.pdf")
	}
}

func TestSafeBaseNameRefusesHiddenFiles(t *testing.T) {
	for _, name := range []string{".envrc", "dir/.zshrc", `C:\tmp\.bashrc`} {
		if _, err := safeBaseName(name); exitCode(err) != errfmt.ExitUsage {
			t.Fatalf("%q: expected usage error, got: %v", name, err)
		}
	}
}

func TestSafeBaseNameRefusesUnusableNames(t *testing.T) {
	for _, name := range []string{"/", "", "."} {
		if _, err := safeBaseName(name); err == nil {
			t.Fatalf("%q: expected error", name)
		}
	}
}

func TestExtractFileName(t *testing.T) {
	name, ok := extractFileName(map[string]any{"Attachable": map[string]any{"FileName": "receipt.pdf"}})
	if !ok || name != "receipt.pdf" {
		t.Fatalf("got %q, %v", name, ok)
	}
	if _, ok := extractFileName(map[string]any{}); ok {
		t.Fatal("expected no file name")
	}
}

func TestWriteDestRefusesExistingWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.pdf")
	if err := os.WriteFile(path, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := writeDest(path, strings.NewReader("new"), false)
	if exitCode(err) != errfmt.ExitUsage {
		t.Fatalf("expected usage error, got: %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "precious" {
		t.Fatalf("existing file was modified: %q", got)
	}
}

func TestWriteDestOverwritesWithForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.pdf")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	n, err := writeDest(path, strings.NewReader("new"), true)
	if err != nil || n != 3 {
		t.Fatalf("force write: n=%d err=%v", n, err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Fatalf("got %q, want %q", got, "new")
	}
}

func TestWriteDestForceReplacesSymlinkNameNotTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if _, err := writeDest(link, strings.NewReader("payload"), true); err != nil {
		t.Fatalf("force over symlink: %v", err)
	}

	got, _ := os.ReadFile(target)
	if string(got) != "target" {
		t.Fatalf("symlink target was written through: %q", got)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("link should now be a regular file: %v %v", fi, err)
	}
	if got, _ := os.ReadFile(link); string(got) != "payload" {
		t.Fatalf("destination content: %q", got)
	}
}

func TestWriteDestRefusesSymlinkWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if _, err := writeDest(link, strings.NewReader("payload"), false); err == nil {
		t.Fatal("expected error writing over symlink without force")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "target" {
		t.Fatalf("symlink target was written through: %q", got)
	}
}

func TestWriteDestForcePreservesOriginalOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.pdf")
	if err := os.WriteFile(path, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}

	// An over-limit body fails after the copy; the original must survive
	// because the write went to a temp file, and the temp must be gone.
	_, err := writeDest(path, &infiniteReader{}, true)
	if err == nil {
		t.Fatal("expected size-limit error")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "precious" {
		t.Fatalf("original destroyed on failed force download: %q", got)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*.partial"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

func TestWriteDestNewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.pdf")
	n, err := writeDest(path, strings.NewReader("data"), false)
	if err != nil || n != 4 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

// infiniteReader never ends, driving writes past maxUploadSize.
type infiniteReader struct{}

func (infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
