package engine

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"xrayrelay/internal/coreversion"
)

const maxArchiveSize int64 = 200 << 20
const maxExtractSize int64 = 600 << 20

type release struct {
	Archive      string
	SHA256       string
	Version      string
	Architecture string
	directory    string
}

func releaseAsset(arch string) (string, error) {
	switch arch {
	case "amd64":
		return "Xray-linux-64.zip", nil
	case "arm64":
		return "Xray-linux-arm64-v8a.zip", nil
	default:
		return "", fmt.Errorf("unsupported Linux architecture %q", arch)
	}
}
func validateVersion(v string) error {
	return coreversion.Validate(v)
}
func parseChecksum(data []byte) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SHA2-256=") || strings.HasPrefix(line, "SHA256=") {
			_, value, _ := strings.Cut(line, "=")
			value = strings.ToLower(strings.TrimSpace(value))
			b, err := hex.DecodeString(value)
			if err == nil && len(b) == 32 {
				return value, nil
			}
		}
	}
	return "", errors.New("official digest did not contain a valid SHA2-256 checksum")
}
func releaseClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("too many release redirects")
		}
		h := req.URL.Hostname()
		if req.URL.Scheme != "https" || (h != "github.com" && h != "release-assets.githubusercontent.com" && h != "objects.githubusercontent.com") {
			return errors.New("release redirected outside official GitHub HTTPS hosts")
		}
		return nil
	}}
}
func fetchLimited(ctx context.Context, client *http.Client, address string, dst io.Writer, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("official fixed-version asset unavailable (HTTP %d); no latest fallback is allowed", resp.StatusCode)
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return errors.New("official asset exceeds size limit")
	}
	return nil
}
func downloadRelease(ctx context.Context, dataDir, version, arch string) (release, error) {
	var r release
	version, err := coreversion.Normalize(version)
	if err != nil {
		return r, err
	}
	asset, err := releaseAsset(arch)
	if err != nil {
		return r, err
	}
	dir := filepath.Join(dataDir, "downloads")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return r, err
	}
	stage, err := os.MkdirTemp(dir, "release-")
	if err != nil {
		return r, err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(stage)
		}
	}()
	base := "https://github.com/XTLS/Xray-core/releases/download/" + version + "/" + asset
	client := releaseClient()
	var digest strings.Builder
	if err := fetchLimited(ctx, client, base+".dgst", &digest, 16<<10); err != nil {
		return r, fmt.Errorf("download official checksum: %w", err)
	}
	sum, err := parseChecksum([]byte(digest.String()))
	if err != nil {
		return r, err
	}
	file := filepath.Join(stage, "core.zip")
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return r, err
	}
	h := sha256.New()
	err = fetchLimited(ctx, client, base, io.MultiWriter(f, h), maxArchiveSize)
	closeErr := f.Close()
	if err != nil {
		return r, fmt.Errorf("download official core: %w", err)
	}
	if closeErr != nil {
		return r, closeErr
	}
	if hex.EncodeToString(h.Sum(nil)) != sum {
		return r, errors.New("official core SHA256 mismatch")
	}
	r = release{Archive: file, SHA256: sum, Version: version, Architecture: arch, directory: stage}
	ok = true
	return r, nil
}
func verifyArchive(file, expected string) error {
	if len(expected) != 64 {
		return errors.New("invalid expected archive SHA256")
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxArchiveSize+1))
	if err != nil {
		return err
	}
	if n > maxArchiveSize {
		return errors.New("archive exceeds size limit")
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(expected) {
		return errors.New("core archive SHA256 mismatch")
	}
	return nil
}

// extractCore validates every archive entry before extracting only the official executable.
func extractCore(archive, destination string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > 256 {
		return errors.New("core archive has too many entries")
	}
	var core *zip.File
	var total uint64
	for _, f := range zr.File {
		name := f.Name
		if strings.Contains(name, "\\") || strings.Contains(name, ":") || path.IsAbs(name) || path.Clean(name) != strings.TrimSuffix(name, "/") || name == ".." || strings.HasPrefix(name, "../") {
			return errors.New("unsafe core archive path")
		}
		if f.Mode()&os.ModeSymlink != 0 || (!f.FileInfo().IsDir() && !f.Mode().IsRegular()) {
			return errors.New("core archive contains a non-regular file")
		}
		total += f.UncompressedSize64
		if total > uint64(maxExtractSize) {
			return errors.New("expanded core archive exceeds size limit")
		}
		if name == "xray" {
			if core != nil {
				return errors.New("duplicate core executable")
			}
			core = f
		}
	}
	if core == nil {
		return errors.New("official archive has no xray executable")
	}
	r, err := core.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, maxExtractSize+1))
	if err == nil && n > maxExtractSize {
		err = errors.New("core executable exceeds size limit")
	}
	if err == nil {
		err = f.Sync()
	}
	c := f.Close()
	if err != nil {
		os.Remove(destination)
		return err
	}
	return c
}
