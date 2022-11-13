package lib

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/plus3it/gorecurcopy"
)

func EnsureDir(dir string) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("couldn't make dirs: %w", err)
	}
	return nil
}

func PathExists(d string) bool {
	_, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

func CopyFile(src, dest string) error {
	fstat, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("Error opening %s to copy: %w", src, err)
	}

	if (fstat.Mode() & os.ModeSymlink) == os.ModeSymlink {
		// TODO - should we?
		return fmt.Errorf("Refusing to copy symlink")
	}

	if err := EnsureDir(filepath.Dir(dest)); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, fstat.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	// TODO - copy xattrs?

	return out.Close()
}

func MountTmpfs(dest, size string) error {
	if err := EnsureDir(dest); err != nil {
		return fmt.Errorf("Failed making mount point: %w", err)
	}
	flags := uintptr(syscall.MS_NODEV | syscall.MS_NOSUID | syscall.MS_NOEXEC)
	err := syscall.Mount("tmpfs", dest, "tmpfs", flags, "size="+size)
	if err != nil {
		return fmt.Errorf("Failed mounting tmpfs onto %s: %w", dest, err)
	}
	return nil
}

func genPassphrase(nchars int) (string, error) {
	// each random byte will give us two characters.  We prefix with
	// trust-.  So if we want 39 or 40 characters, request (39-6)/2+1 = 17
	// bytes, giving us 136 bits of randomness.

	nbytes := (nchars - 6) / 2 + 1
	rand, err := HWRNGRead(nbytes)
	if err != nil {
		return "", err
	}
	s := "trust-" + hex.EncodeToString(rand)
	s = s[:nchars]
	return s, nil
}

func runWithStdin(stdinString string, args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("%s: %s", strings.Join(args, " "), err)
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, stdinString)
	}()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s: %s", strings.Join(args, " "), err, string(output))
	}
	return nil
}

func luksOpen(path, key, plaintextPath string) error {
	return runWithStdin(key,
		"cryptsetup", "open", "--type=luks", "--key-file=-", path, plaintextPath)
}

func luksFormatLuks2(path, key string) error {
	return runWithStdin(key, "cryptsetup", "luksFormat", "--type=luks2", "--key-file=-", path)
}

// if src == /tmp/a and dst == /tmp/b, and /tmp/a/x exists, then make
// sure we have /tmp/b/x.
// The way gorecurcopy.CopyDirectory() works, if $dest does not exists, it
// will fail, so create it first.
func CopyFiles(src, dest string) error {
	if !PathExists(src) {
		return fmt.Errorf("No such directory: %s", src)
	}
	if err := EnsureDir(dest); err != nil {
		return err
	}
	return gorecurcopy.CopyDirectory(src, dest)
}
