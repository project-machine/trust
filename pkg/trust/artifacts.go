package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/apex/log"
	efi "github.com/canonical/go-efilib"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/umoci"
	"github.com/opencontainers/umoci/oci/casext"
	"github.com/opencontainers/umoci/oci/layer"
	"github.com/pkg/errors"
	"github.com/project-machine/bootkit/pkg/cert"
	"github.com/project-machine/bootkit/pkg/shim"
	"github.com/project-stacker/stacker/container/idmap"
	"github.com/project-stacker/stacker/lib"
	stackeroci "github.com/project-stacker/stacker/oci"
)

func extractSingleSquash(squashFile string, extractDir string) error {
	err := os.MkdirAll(extractDir, 0755)
	if err != nil {
		return err
	}

	cmd := []string{"unsquashfs", "-f", "-d", extractDir, squashFile}
	return RunCommand(cmd...)
}

func unpackSquashLayer(ociDir string, oci casext.Engine, tag string, dest string) error {
	rootfsDir := filepath.Join(dest, "rootfs")
	manifest, err := stackeroci.LookupManifest(oci, tag)
	if err != nil {
		return errors.Wrapf(err, "Failed finding %s in oci layout", tag)
	}

	for _, layer := range manifest.Layers {
		squashFile := filepath.Join(ociDir, "blobs/sha256", layer.Digest.Encoded())
		if err := extractSingleSquash(squashFile, rootfsDir); err != nil {
			return errors.Wrapf(err, "Failed extracting squashfs")
		}
	}

	return nil
}

func GetRootlessMapOptions() (layer.MapOptions, error) {
	opts := layer.MapOptions{Rootless: true}
	idmapSet, err := idmap.ResolveCurrentIdmapSet()
	if err != nil {
		return opts, err
	}

	if idmapSet == nil {
		return opts, errors.Errorf("no uids mapped for current user")
	}

	for _, idm := range idmapSet.Idmap {
		if err := idm.Usable(); err != nil {
			return opts, errors.Errorf("idmap unusable: %s", err)
		}

		if idm.Isuid {
			opts.UIDMappings = append(opts.UIDMappings, rspec.LinuxIDMapping{
				ContainerID: uint32(idm.Nsid),
				HostID:      uint32(idm.Hostid),
				Size:        uint32(idm.Maprange),
			})
		}

		if idm.Isgid {
			opts.GIDMappings = append(opts.GIDMappings, rspec.LinuxIDMapping{
				ContainerID: uint32(idm.Nsid),
				HostID:      uint32(idm.Hostid),
				Size:        uint32(idm.Maprange),
			})
		}
	}

	return opts, nil
}

func UnpackLayer(ociDir string, oci casext.Engine, tag string, dest string) error {
	manifest, err := stackeroci.LookupManifest(oci, tag)
	if err != nil {
		return errors.Wrapf(err, "couldn't find '%s' in oci", tag)
	}

	if manifest.Layers[0].MediaType == ispec.MediaTypeImageLayer ||
		manifest.Layers[0].MediaType == ispec.MediaTypeImageLayerGzip {
		os := layer.UnpackOptions{KeepDirlinks: true}
		os.MapOptions, err = GetRootlessMapOptions()
		if err != nil {
			return errors.Wrapf(err, "Failed getting rootless map options")
		}
		err = umoci.Unpack(oci, tag, dest, os)
		if err != nil {
			return errors.Wrapf(err, "Failed unpacking layer")
		}
	} else {
		if err := unpackSquashLayer(ociDir, oci, tag, dest); err != nil {
			return errors.Wrapf(err, "Failed unpacking squashfs")
		}
	}
	return nil
}

func unpackLayerRootfs(ociDir string, oci casext.Engine, tag string, extractTo string) error {
	xdir := filepath.Join(extractTo, ".extract")
	rootfs := filepath.Join(xdir, "rootfs")
	defer os.RemoveAll(xdir)

	if err := UnpackLayer(ociDir, oci, tag, xdir); err != nil {
		return errors.Wrapf(err, "Failed unpacking layer")
	}

	entries, err := os.ReadDir(rootfs)
	if err != nil {
		return errors.Wrapf(err, "failed reading directory entries")
	}

	for _, entry := range entries {
		if err := os.Rename(filepath.Join(rootfs, entry.Name()), filepath.Join(extractTo, entry.Name())); err != nil {
			return errors.Wrapf(err, "Failed moving contents to %s", extractTo)
		}
	}
	return nil
}

func UpdateShim(inShim, newShim, keysetPath string) error {
	sigdataList, err := cert.LoadSignatureDataDirs(
		filepath.Join(keysetPath, "uki-limited"),
		filepath.Join(keysetPath, "uki-production"),
		filepath.Join(keysetPath, "uki-tpm"),
	)
	if err != nil {
		return errors.Wrapf(err, "Failed LoadSignatureDataDirs")
	}

	err = RunCommand("sbattach", "--remove", inShim)
	if err != nil {
		return errors.Wrapf(err, "failed stripping signature from shim")
	}

	err = shim.SetVendorDB(inShim, cert.NewEFISignatureDatabase(sigdataList),
		cert.NewEFISignatureDatabase([]*efi.SignatureData{}))

	cmd := []string{"sbsign",
		"--key", filepath.Join(keysetPath, "uefi-db", "privkey.pem"),
		"--cert", filepath.Join(keysetPath, "uefi-db", "cert.pem"),
		"--output", newShim, inShim}
	err = RunCommand(cmd...)
	if err != nil {
		return errors.Wrapf(err, "failed re-signing shim")
	}

	return nil
}

func SetupBootkit(keysetName, bootkitVersion string) error {
	// TODO - we have to fix this by
	// a. having bootkit generate arm64
	// b. changing the bootkit layer naming to reflect arch
	// c. using the bootkit api here instead of doing it ourselves
	// for now, we just do nothing on arm64
	if runtime.GOARCH != "amd64" {
		log.Warnf("Running on %q, so not building bootkit artifacts (only amd64 supported).", runtime.GOARCH)
		return nil
	}

	tmpdir, err := os.MkdirTemp("", "trust-bootkit")
	if err != nil {
		return errors.Wrapf(err, "Failed creating temporary directory")
	}
	defer os.RemoveAll(tmpdir)

	home, err := os.UserHomeDir()
	if err != nil {
		return errors.Wrapf(err, "couldn't find home dir")
	}
	ociDir := filepath.Join(home, ".cache", "machine", "trust", "bootkit", "oci")
	bootkitLayer := "bootkit:" + bootkitVersion + "-squashfs"
	EnsureDir(ociDir)
	cachedOci := fmt.Sprintf("oci:%s:%s", ociDir, bootkitLayer)
	err = lib.ImageCopy(lib.ImageCopyOpts{
		Src:      fmt.Sprintf("docker://zothub.io/machine/bootkit/%s", bootkitLayer),
		Dest:     cachedOci,
		Progress: os.Stdout,
	})
	if err != nil {
		return errors.Wrapf(err, "Failed copying pristine bootkit")
	}

	oci, err := umoci.OpenLayout(ociDir)
	if err != nil {
		return errors.Wrapf(err, "Failed opening layout %s", ociDir)
	}
	defer oci.Close()

	bDir := filepath.Join(tmpdir, "bootkit")
	err = unpackLayerRootfs(ociDir, oci, bootkitLayer, bDir)
	if err != nil {
		return errors.Wrapf(err, "Failed unpacking bootkit layer")
	}

	// Now we have a directory 'bootkit/bootkit' let's flatten that for convenience
	os.Rename(filepath.Join(bDir, "bootkit"), bDir+".tmp")
	os.RemoveAll(bDir)
	os.Rename(bDir+".tmp", bDir)
	mosKeyPath, err := getMosKeyPath()
	if err != nil {
		return errors.Wrapf(err, "Failed getting mos keypath")
	}

	keysetPath := filepath.Join(mosKeyPath, keysetName)
	destDir := filepath.Join(keysetPath, "bootkit")
	if err := EnsureDir(destDir); err != nil {
		return errors.Wrapf(err, "Failed creating directory %q", destDir)
	}

	unchanged := []string{"boot.tar", "modules.squashfs", "ovmf-code.fd", "ovmf-vars-empty.fd"}
	for _, f := range unchanged {
		if err := CopyFile(filepath.Join(bDir, f), filepath.Join(destDir, f)); err != nil {
			return errors.Wrapf(err, "Failed copying %s into new bootkit from %s -> %s", f, bDir, destDir)
		}
	}

	err = UpdateShim(filepath.Join(bDir, "shim.efi"), filepath.Join(destDir, "shim.efi"), keysetPath)
	if err != nil {
		return errors.Wrapf(err, "Failed updating the shim")
	}

	// break apart kernel.efi to replace the manifestCert.pem
	newKernel, err := ReplaceManifestCert(bDir, filepath.Join(keysetPath, "manifest-ca", "cert.pem"))
	if err != nil {
		return errors.Wrapf(err, "Failed replacing manifest certificate")
	}
	cmd := []string{"sbsign",
		"--key", filepath.Join(keysetPath, "uki-limited", "privkey.pem"),
		"--cert", filepath.Join(keysetPath, "uki-limited", "cert.pem"),
		"--output", filepath.Join(destDir, "kernel.efi"),
		newKernel}
	err = RunCommand(cmd...)
	if err != nil {
		return errors.Wrapf(err, "failed re-signing shim")
	}

	// generate a new ovmf-vars.fd
	pkGuidBytes, err := os.ReadFile(filepath.Join(keysetPath, "uefi-pk", "guid"))
	if err != nil {
		return errors.Wrapf(err, "failed reading uefi-pk guid")
	}
	pkGuid := strings.TrimSpace(string(pkGuidBytes))
	kekGuidBytes, err := os.ReadFile(filepath.Join(keysetPath, "uefi-kek", "guid"))
	if err != nil {
		return errors.Wrapf(err, "failed reading uefi-kek guid")
	}
	kekGuid := strings.TrimSpace(string(kekGuidBytes))
	dbGuidBytes, err := os.ReadFile(filepath.Join(keysetPath, "uefi-db", "guid"))
	if err != nil {
		return errors.Wrapf(err, "failed reading uefi-db guid")
	}
	dbGuid := strings.TrimSpace(string(dbGuidBytes))

	outFile := filepath.Join(destDir, "ovmf-vars.fd")
	cmd = []string{
		"virt-fw-vars",
		"--input=/usr/share/OVMF/OVMF_VARS.fd",
		"--output", outFile,
		"--secure-boot", "--no-microsoft",
		"--set-pk", pkGuid, filepath.Join(keysetPath, "uefi-pk", "cert.pem"),
		"--add-kek", kekGuid, filepath.Join(keysetPath, "uefi-kek", "cert.pem"),
		"--add-db", dbGuid, filepath.Join(keysetPath, "uefi-db", "cert.pem"),
	}
	if err := RunCommand(cmd...); err != nil {
		return errors.Wrapf(err, "Failed creating new ovmf vars")
	}

	return nil
}

func findSection(lines []string, which string) (int64, int64, bool) {
	for _, l := range lines {
		if strings.Contains(l, which) {
			s := strings.Fields(l)
			if len(s) != 7 {
				return 0, 0, false
			}
			sz, err := strconv.ParseInt(s[2], 16, 64)
			if err != nil {
				return 0, 0, false
			}
			off, err := strconv.ParseInt(s[5], 16, 64)
			if err != nil {
				return 0, 0, false
			}
			return off, sz, true
		}
	}
	return 0, 0, false
}

func extractObj(objdump []string, dir string, piece string) error {
	outName := filepath.Join(dir, piece+".out")
	offset, size, found := findSection(objdump, piece)
	if !found {
		return fmt.Errorf("Symbol %s not found", piece)
	}
	objPath := filepath.Join(dir, "kernel.efi")
	// Yes we could do this all without shelling out...
	err := RunCommand("dd", "if="+objPath, "of="+outName,
		fmt.Sprintf("skip=%d", offset),
		fmt.Sprintf("count=%d", size),
		"iflag=skip_bytes,count_bytes")
	if err != nil {
		return err
	}
	return nil
}

// extract the pieces of kernel.efi that we want to known names
func extractObjs(dir string) error {
	kName := filepath.Join(dir, "kernel.efi")
	stdout, stderr, err := RunWithStdall("", "objdump", "-h", kName)
	if err != nil {
		return errors.Wrapf(err, "Failed running objdump:\n stdout: %s\nstderr: %s", stdout, stderr)
	}
	lines := strings.Split(string(stdout), "\n")
	//pieces := []string{"sbat", "cmdline", "initrd", "linux"}
	// Actually we only need the initrd, I believe
	pieces := []string{"initrd"}
	for _, piece := range pieces {
		if err := extractObj(lines, dir, piece); err != nil {
			return errors.Wrapf(err, "Failed extracting %s", piece)
		}
	}
	return nil
}

// Given a tempdir with a kernel.efi, take apart the kernel.efi.  In its
// initrd, replace /manifestCert.pem with the newcert argument.  Rebuild
// into a new kernel.efi and return that filename.  Note that the filename
// will always be ${dir}/newkernel.efi, but whatever.
func ReplaceManifestCert(dir, newCert string) (string, error) {
	if err := extractObjs(dir); err != nil {
		return "", errors.Wrapf(err, "Failed extracting objects")
	}
	initrd := filepath.Join(dir, "initrd")
	initrdgz := initrd + ".gz"
	os.Rename(filepath.Join(dir, "initrd.out"), initrdgz)
	if err := RunCommand("gunzip", initrdgz); err != nil {
		return "", errors.Wrapf(err, "Failed unzipping initrd.gz")
	}
	emptydir := filepath.Join(dir, "empty")
	if err := EnsureDir(emptydir); err != nil {
		return "", errors.Wrapf(err, "Failed creating empty directory")
	}

	if err := CopyFile(newCert, filepath.Join(emptydir, "manifestCA.pem")); err != nil {
		return "", errors.Wrapf(err, "Failed copying manifest into empty dir")
	}

	bashcmd := "cd " + emptydir + "; echo ./manifestCA.pem | cpio --create --owner=+0:+0 -H newc --quiet >> " + filepath.Join(dir, "initrd")
	if err := RunCommand("/bin/bash", "-c", bashcmd); err != nil {
		return "", errors.Wrapf(err, "Failed extracting initrd")
	}

	if err := RunCommand("gzip", initrd); err != nil {
		return "", errors.Wrapf(err, "Failed re-zipping initrd.gz")
	}

	// Now build a new kernel.efi using the new initrd.gz
	k1 := filepath.Join(dir, "kernel.efi")
	if err := RunCommand("sbattach", "--remove", k1); err != nil {
		return "", errors.Wrapf(err, "Failed removing signature from original kernel.efi")
	}
	k2 := filepath.Join(dir, "kernel.tmp")
	kret := filepath.Join(dir, "newkernel.efi")
	if err := RunCommand("objcopy", "--remove-section=.initrd", k1, k2); err != nil {
		return "", errors.Wrapf(err, "Failed removing old initrd from kernel.efi")
	}

	err := RunCommand("objcopy",
		"--add-section=.initrd="+initrdgz,
		"--change-section-vma=.initrd=0x3000000",
		k2, kret)
	if err != nil {
		return "", errors.Wrapf(err, "Failed inserting new initrd into kernel.efi")
	}
	return kret, nil
}
