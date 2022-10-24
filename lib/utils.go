package lib

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
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
