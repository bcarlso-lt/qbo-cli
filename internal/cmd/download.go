package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/voska/qbo-cli/internal/errfmt"
	"github.com/voska/qbo-cli/internal/output"
)

type DownloadCmd struct {
	ID     string `arg:"" help:"Attachable ID to download."`
	Output string `name:"output" short:"o" help:"Save to this file path instead of original filename."`
	URL    bool   `name:"url" help:"Print the temporary download URL instead of saving the file."`
}

func (c *DownloadCmd) Run(g *Globals) error {
	if g.CLI.DryRun {
		output.Hint("[dry-run] GET /v3/company/{id}/download/%s", c.ID)
		return nil
	}

	client, _, err := g.NewAPIClient()
	if err != nil {
		return err
	}

	if c.URL {
		url, err := client.FetchDownloadURL(g.Ctx, c.ID)
		if err != nil {
			return err
		}
		return WriteOutput(g.Ctx, map[string]any{"url": url})
	}

	savePath := c.Output
	if savePath == "" {
		meta, err := client.Read(g.Ctx, "attachable", c.ID)
		if err != nil {
			return err
		}
		name, _ := extractFileName(meta)
		if name == "" {
			return errfmt.Usage("attachable " + c.ID + " has no file name — pass -o to choose an output path")
		}
		savePath, err = safeBaseName(name)
		if err != nil {
			return err
		}
	}

	// Check before spending API calls: the attachable read above, the
	// download-URL fetch, and the body stream are all wasted if the
	// destination is already taken. Lstat (not Stat) so a planted symlink
	// counts as "exists" instead of being probed through.
	if !g.CLI.Force {
		if _, err := os.Lstat(savePath); err == nil {
			return errfmt.Usage(savePath + " already exists — pass --force to overwrite")
		}
	}

	body, err := client.Download(g.Ctx, c.ID)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()

	n, err := writeDest(savePath, body, g.CLI.Force)
	if err != nil {
		return err
	}

	output.Hint("saved %s (%d bytes)", savePath, n)
	return WriteOutput(g.Ctx, map[string]any{"id": c.ID, "path": savePath, "bytes": n})
}

// writeDest saves the stream to path without ever damaging an existing file.
// Without force, the destination is created with O_EXCL, so nothing existing
// is truncated and a pre-planted symlink is never followed. With force, the
// stream lands in a temp file first and is renamed over the destination only
// after a complete, flushed write — the original survives a mid-stream
// failure, and the destination name is replaced (never written through, so a
// symlink there redirects nothing).
func writeDest(path string, body io.Reader, force bool) (int64, error) {
	if force {
		tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.partial")
		if err != nil {
			return 0, errfmt.Wrap(errfmt.ExitError, "cannot create temp file", err)
		}
		n, err := writeAndClose(tmp, body)
		if err != nil {
			return 0, err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			_ = os.Remove(tmp.Name())
			return 0, errfmt.Wrap(errfmt.ExitError, "cannot replace existing file", err)
		}
		if err := os.Rename(tmp.Name(), path); err != nil {
			_ = os.Remove(tmp.Name())
			return 0, errfmt.Wrap(errfmt.ExitError, "cannot move file into place", err)
		}
		return n, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return 0, errfmt.Usage(path + " already exists — pass --force to overwrite")
		}
		return 0, errfmt.Wrap(errfmt.ExitError, "cannot create file", err)
	}
	return writeAndClose(f, body)
}

// writeAndClose copies the body into f, enforcing the size cap and surfacing
// close/flush errors. On any failure the partial file is removed — it is
// either an O_EXCL-created destination (cannot have pre-existed) or a temp
// file, so an original is never deleted.
func writeAndClose(f *os.File, body io.Reader) (int64, error) {
	n, err := io.Copy(f, io.LimitReader(body, maxUploadSize+1))
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return 0, errfmt.Wrap(errfmt.ExitError, "cannot write file", err)
	}
	if n > maxUploadSize {
		_ = os.Remove(f.Name())
		return 0, errfmt.New(errfmt.ExitError, fmt.Sprintf("download exceeds %d byte limit", maxUploadSize))
	}
	return n, nil
}

// extractFileName pulls the original file name from an attachable read
// response. The bool reports whether the field was present.
func extractFileName(meta map[string]any) (string, bool) {
	att, _ := meta["Attachable"].(map[string]any)
	name, _ := att["FileName"].(string)
	return name, name != ""
}

// safeBaseName reduces an API-supplied file name to a bare name that is safe
// to create in the working directory. The name comes from the QBO response,
// which anyone with write access to the company controls: directory parts
// are stripped (both separator styles — filepath.Base ignores backslashes on
// Unix), and hidden files are refused because a dropped .envrc or .zshrc is
// an attack, not a download.
func safeBaseName(name string) (string, error) {
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	name = filepath.Base(name)
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "", errfmt.Usage("attachable file name is unusable — pass -o to choose an output path")
	}
	if strings.HasPrefix(name, ".") {
		return "", errfmt.Usage(fmt.Sprintf("refusing to write hidden file %q from API-supplied name — pass -o to choose an output path", name))
	}
	return name, nil
}
