package lib

// This is the entrypoint for the tpm2 based provisioner

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/apex/log"
	"github.com/jsipprell/keyctl"
	"github.com/urfave/cli"
)

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

type tpm2V3Context struct {
	dataDir        string  // our data directory under which we keep files
	keyClass       string  // release, dev, or snakeoil
	adminPwd        string  // provisioned tpm admin password
	pubkeyName     string  // pubkeyname from tpm2_loadexternal
	pubkeyContext  string  // pubkeycontext from tpm2_loadexternal
	tmpDir         string  // directory for tpm2 sessions and other io
	sessionFile    string
	Keyctx         string  // pathname to file from tpm2_createprimary
}

// We're not doing partitioning yet.  Just expect "/signdata"
func mountPlaintextPartition() (string, error) {
	return "/", nil
}

// /signdata/pcr7/ may have "policy-1", "policy-2", etc.  If
// not, return "".  If so, return the policy-N for highest N.
func getPoldir(pdir string) string {
	n := -1
	dirname := ""
	dents, err := os.ReadDir(pdir)
	if err != nil {
		return ""
	}
	for _, ent := range dents {
		if !ent.IsDir() {
			continue
		}
		f := ent.Name()
		if !strings.HasPrefix(f, "policy-") {
			continue
		}
		m, err := strconv.Atoi(f[7:])
		if err != nil {
			continue
		}
		if m > n {
			n = m
			dirname = filepath.Join(pdir, f)
		}
	}
	return dirname
}

// ChooseSignData:
// Input argument:
//    pbfMount: the sb-tpm plaintext partition (pbf) is
// Returns:
//    1. the signdata directory name for this host's pcr7 value
//    2. the type of key this was signed by (e.g. "production")
func ChooseSignData(pbfMount string) (string, string, error) {
	signDir := filepath.Join(pbfMount, "pcr7data")
	polDir := getPoldir(signDir)
	if polDir == "" {
		return "", "", fmt.Errorf("no policy dir found")
	}
	pcr7, err := curPcr7()
	if err != nil {
		return "", "", fmt.Errorf("Failed reading pcr7 from TPM: %w", err)
	}

	// If pcr7 is d237368f4369bc21222040606963d4f3341bd0acc98b23dbb529a81b89c6b81e,
	// then the information for this pcr7 signed smoosh will be under the directory
	// signdata/policy-N/d2/37368f4369bc21222040606963d4f3341bd0acc98b23dbb529a81b89c6b81e
	pcr7Dir := filepath.Join(polDir, pcr7[:2], pcr7[2:])

	var info signDataInfo
	infoPath := filepath.Join(pcr7Dir, "info.json")
	infoBytes, err := ioutil.ReadFile(infoPath)
	if err != nil {
		return "", "", fmt.Errorf("Failed reading pcr7data infofile: %w", err)
	}

	err = json.Unmarshal(infoBytes, &info)
	if err != nil {
		return "", "", fmt.Errorf("Failed unmarshalling pcr7data infofile: %w", err)
	}
	if info.Type != productionKey {
		return "", "", fmt.Errorf("PCR7 is for %s, not production key", info.Type)
	}
	return pcr7Dir, info.Class, nil
}

func NewTpm2() (*tpm2V3Context, error) {
	t := &tpm2V3Context{}
	tmpd, err := ioutil.TempDir("/run", "atx-trustroot-*")
	if err != nil {
		return t, fmt.Errorf("failed to create tempdir: %w", err)
	}

	pbfMount, err := mountPlaintextPartition()
	if err != nil {
		return t, err
	}

	dataDir, keyClass, err := ChooseSignData(pbfMount)
	if err != nil {
		return t, fmt.Errorf("failed finding pcr7 data: %w", err)
	}

	t = &tpm2V3Context{
		dataDir:        dataDir,
		tmpDir:         tmpd,
		keyClass:       keyClass,
	}
	return t, nil
}

// Set up the /priv/factor/secure mounts+dirs
// Return the final directory name.
func setupFactory() (string, error) {
	// can't move-mount out of a MS_SHARED parent, which / is,
	// so create a MS_SLAVE parent directory.
	priv := "/priv"
	err := EnsureDir(priv)
	if err != nil {
		return "", fmt.Errorf("failed creating directory %s: %w", priv, err)
	}
	err = syscall.Mount(priv, priv, "", syscall.MS_BIND, "")
	if err != nil {
		return "", fmt.Errorf("failed to make /priv a bind mount: %w", err)
	}
	err = syscall.Mount("none", priv, "", syscall.MS_SLAVE, "")
	if err != nil {
		return "", fmt.Errorf("failed to make /priv not shared: %w", err)
	}

	tmpfsDir := filepath.Join(priv, "factory")
	if err = os.Chmod(tmpfsDir, 0644); err != nil {
		return "", fmt.Errorf("Failed making tmpfs private: %w", err)
	}

	dest := filepath.Join(tmpfsDir, "secure")

	if err = MountTmpfs(tmpfsDir, "1G"); err != nil {
		return "", fmt.Errorf("Failed creating tmpfs for certs: %w", err)
	}
	if err = os.Chmod(tmpfsDir, 0644); err != nil {
		return "", fmt.Errorf("Failed making tmpfs private: %w", err)
	}

	if PathExists(PBFMountpoint) {
		privpbf := filepath.Join(priv, PBFMountpoint)
		err = EnsureDir(privpbf)
		if err != nil {
			log.Warnf("Failed creating %s", privpbf)
		}
		err = syscall.Mount(PBFMountpoint, privpbf, "", syscall.MS_BIND, "")
		if err != nil {
			log.Warnf("Failed bind mounting %s to %s: %v", PBFMountpoint, privpbf, err)
		}
	}

	err = os.Mkdir(dest, 0700)
	if err !=  nil {
		return dest, fmt.Errorf("Could not create %s on tmpfs: %w", dest, err)
	}
	return dest, nil
}

func (t *tpm2V3Context) Close() {
	if t.tmpDir != "" {
		err := os.RemoveAll(t.tmpDir)
		if err != nil {
			log.Warnf("Error removing data dir %s: %v", t.dataDir, err)
		}
	}
}

type KeyType string
const (
	limitedKey    KeyType = "limited"
	productionKey KeyType = "production"
	tpmpassKey    KeyType = "password"
)

type signDataInfo struct {
	Class   string  `json:"key"`      // Was this pcr7 value from release, dev, or snakeoil keys
	Type    KeyType `json:"key_type"` // Which of the three types of kernel signing keys
	EstDate string  `json:"est_date"` // The 'established' date for this PCR7 value
	Comment string  `json:"comment"`  // More information about the hardware+firmware
}

func (c *tpm2V3Context) Pubkeypath(poltype string) string {
	// c.dataDir is the /signdata/policy-N/XX/YYYYYYYYYY directory where
	// XXYYYYYYYYYY... is the pcr7.  The actual EA policy signing keys are
	// under /signdata/policy-N/pubkeys/.  So we calculate ../.. of c.dataDir
	p := filepath.Dir(c.dataDir)
	p = filepath.Dir(p)

	// There are (currently) 6 public keys, e.g. luks-snakeoil.pem.  Build the
	// filename here based on the type of keys we know we have (based on pcr7).
	fname := fmt.Sprintf("%s-%s.pem", poltype, c.keyClass)

	return filepath.Join(p, "pubkeys", fname)
}

func (t *tpm2V3Context) ExtendPCR7() error {
	return t.extendPCR7()
}

func (t *tpm2V3Context) TpmGenPolicy(ctx *cli.Context) error {
	return TpmGenPolicy(ctx)
}

func (t *tpm2V3Context) Provision(certPath, keyPath string) error {
	err := HWRNGSeed()
	if err != nil {
		return fmt.Errorf("Failed to seed hardware random: %v", err)
	}

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("Failed reading provisioned cert %s: %w", certPath, err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("Failed reading provisioned key %s: %w", keyPath, err)
	}

	log.Infof("Taking ownership of TPM.")
	if err := Tpm2Clear(); err != nil {
		return fmt.Errorf("Unable to clear/take ownership of tpm: %w", err)
	}

	// Admin password on some hardware can't be longer than 32.
	t.adminPwd, err = genPassphrase(32)
	if err != nil {
		return err
	}

	// TODO - save only if debug requested?
	err = os.WriteFile("/run/tpm-passphrase", []byte(t.adminPwd), 0600)
	if err != nil {
		log.Warnf("Unable to save admin passphrase in backup file")
	}

	if err := t.StoreAdminPassword(); err != nil {
		return err
	}

	lv := fmt.Sprintf("%08d", TpmLayoutVersion)
	if err := t.StorePublic(TPM2IndexTPMVersion, lv); err != nil {
		return err
	}

	// store the EA policy version
	log.Debugf("Storing TPM version")
	if err := t.StorePublic(TPM2IndexEAVersion, PolicyVersion.String()); err != nil {
		return err
	}

	// generate a luks passphrase for the CryptPart
	log.Debugf("Generating LUKS passphrase")
	sbsPassphrase, err := genPassphrase(40)
	if err != nil {
		return err
	}

	osPassphrase, err := genPassphrase(40)
	if err != nil {
		return err
	}

	// TODO = partition and create the sbf with sbsPassphrase

	pubkeyPath := t.Pubkeypath("luks")
	err = t.Tpm2LoadExternal(pubkeyPath)
	if err != nil {
		return fmt.Errorf("Failed loading luks policy public key: %w", err)
	}

	err = t.Tpm2StartSession(TrialSession)
	if err != nil {
		return fmt.Errorf("Failed creating trial auth session: %w", err)
	}
	defer t.Tpm2FlushContext()

	policyDigestFile, err := t.Tpm2PolicyAuthorize()
	if err != nil {
		return fmt.Errorf("Failed authorizing PCR policy: %w", err)
	}

	attributes := "ownerwrite|ownerread|policyread"

	log.Debugf("Defining and initializing LuksSecret index %s with attributes: %s", TPM2IndexSBSKey, attributes)
	err = t.Tpm2NVDefine(policyDigestFile, attributes, TPM2IndexSBSKey, len(sbsPassphrase))
	if err != nil {
		return fmt.Errorf("Failed defining SBS Secret NV: %w", err)
	}

	log.Debugf("Defining the provisioned key and certificate NVIndexes")
	err = t.Tpm2NVDefine(policyDigestFile, attributes, TPM2IndexCert, len(certBytes))
	if err != nil {
		return fmt.Errorf("Failed defining NVIndex for provisioned key")
	}
	err = t.Tpm2NVDefine(policyDigestFile, attributes, TPM2IndexKey, len(keyBytes))
	if err != nil {
		return fmt.Errorf("Failed defining NVIndex for provisioned cert")
	}

	attributes = attributes + "|policywrite"
	log.Debugf("Defining and initializing osPassphrase index %s with attributes: %s", TPM2IndexOSKey, attributes)
	err = t.Tpm2NVDefine(policyDigestFile, attributes, TPM2IndexOSKey, len(osPassphrase))
	if err != nil {
		return fmt.Errorf("Failed defining AtxSecret NV: %w", err)
	}

	err = t.Tpm2NVWriteAsAdmin(TPM2IndexCert, string(certBytes))
	if err != nil {
		return fmt.Errorf("Failed writing provisioned cert to TPM: %w", err)
	}

	err = t.Tpm2NVWriteAsAdmin(TPM2IndexKey, string(keyBytes))
	if err != nil {
		return fmt.Errorf("Failed writing provisioned key to TPM: %w", err)
	}

	err = t.Tpm2NVWriteAsAdmin(TPM2IndexSBSKey, sbsPassphrase)
	if err != nil {
		return fmt.Errorf("Failed writing SBS luks passphrase to TPM: %w", err)
	}

	err = t.Tpm2NVWriteAsAdmin(TPM2IndexOSKey, osPassphrase)
	if err != nil {
		return fmt.Errorf("Failed writing initial atx passphrase to TPM: %w", err)
	}

	return nil
}

// Called during signed initrd to extract information from TPM
// and make it available for (signed) userspace.
func (t *tpm2V3Context) InitrdSetup() error {
	defer func() {
		if err := t.ExtendPCR7(); err != nil {
			log.Warnf("Failed extending PCR 7: %v", err)
			run("poweroff")
			log.Fatalf("Failed powering off")
		}
		log.Infof("Extended PCR 7")
	}()

	dest, err := setupFactory()
	if err != nil {
		return err
	}

	signedPolicyPath := filepath.Join(t.dataDir, "tpm_luks.policy.signed")

	provCert, err := t.ReadSecret(TPM2IndexCert, signedPolicyPath)
	if err != nil {
		return fmt.Errorf("Failed reading provisioned certificate: %w", err)
	}
	err = ioutil.WriteFile(filepath.Join(dest, "server.crt"), []byte(provCert), 0600)
	if err != nil {
		return fmt.Errorf("Failed writing provisioned certificate to tmpfs: %w", err)
	}

	privKey, err := t.ReadSecret(TPM2IndexKey, signedPolicyPath)
	if err != nil {
		return fmt.Errorf("Failed reading provisioned key from TPM: %w", err)
	}
	err = ioutil.WriteFile(filepath.Join(dest, "server.key"), []byte(privKey), 0600)
	if err != nil {
		return fmt.Errorf("Failed writing provisioned key to tmpfs: %w", err)
	}
	log.Infof("Copied certs")

	// Load the OS key into the keyring
	osPassphrase, err := t.ReadSecret(TPM2IndexOSKey, signedPolicyPath)
	if err != nil {
		return fmt.Errorf("Failed reading key from TPM: %w", err)
	}

	// see https://mjg59.dreamwidth.org/37333.html
	keyring, err := keyctl.UserKeyring()
	if err != nil {
		return fmt.Errorf("Getting usersession keyring failed: %w", err)
	}
	session, err := keyctl.SessionKeyring()
	if err != nil {
		return fmt.Errorf("Getting session keyring failed: %w", err)
	}
	key, err := session.Add("machine:luks", []byte(osPassphrase))
	if err != nil {
		return fmt.Errorf("Adding key to keyring failed: %w", err)
	}

	if err := keyctl.SetPerm(key, keyctl.PermUserAll|keyctl.PermProcessAll); err != nil {
		return fmt.Errorf("Key permissions setting failed: %w", err)
	}
	if err := keyctl.Link(keyring, key); err != nil {
		return fmt.Errorf("Key link failed: %w", err)
	}
	if err := keyctl.Unlink(session, key); err != nil {
		return fmt.Errorf("Key unlink failed: %w", err)
	}

	err = CopyFile("/manifestCA.pem", filepath.Join(dest, "manifestCA.pem"))
	if err != nil {
		return fmt.Errorf("Failed copying the manifest CA parent: %w", err)
	}

	// But we also need to access this file during initrd, while
	// it's still under /priv.  We could handle this several ways,
	// but let's just copy it to /factory/secure/ as well.
	err = EnsureDir("/factory/secure")
	if err != nil {
		return fmt.Errorf("Failed creating /factory/secure in initrd: %w", err)
	}
	err = CopyFile("/priv/factory/secure/server.crt", "/factory/secure/server.crt")
	if err != nil {
		return fmt.Errorf("Failed copying the server certificate: %w", err)
	}
	err = CopyFile("/manifestCA.pem", "/factory/secure/manifestCA.pem")
	if err != nil {
		log.Warnf("Failed copying manifest CA parent: %w", err)
	}

	return nil
}

// After Provisioning, but before an OS install.  Create a new OS password.
// Put that password in the TPM and in root keyring, then extend PCR7.  Now
// the OS installer can create encrypted filesystems, but cannot read any
// data from a previous install.
func (t *tpm2V3Context) PreInstall() error {
	defer func() {
		if err := t.ExtendPCR7(); err != nil {
			log.Warnf("Failed extending PCR 7: %v", err)
			run("poweroff")
			log.Fatalf("Failed powering off")
		}
		log.Infof("Extended PCR 7")
	}()

	osPassphrase, err := genPassphrase(40)
	if err != nil {
		return err
	}

	err = t.Tpm2NVWriteWithPolicy(TPM2IndexOSKey, osPassphrase)
	if err != nil {
		return fmt.Errorf("Failed writing initial atx passphrase to TPM: %w", err)
	}

	// see https://mjg59.dreamwidth.org/37333.html
	keyring, err := keyctl.UserKeyring()
	if err != nil {
		return fmt.Errorf("Getting usersession keyring failed: %w", err)
	}
	session, err := keyctl.SessionKeyring()
	if err != nil {
		return fmt.Errorf("Getting session keyring failed: %w", err)
	}
	key, err := session.Add("machine:luks", []byte(osPassphrase))
	if err != nil {
		return fmt.Errorf("Adding key to keyring failed: %w", err)
	}

	if err := keyctl.SetPerm(key, keyctl.PermUserAll|keyctl.PermProcessAll); err != nil {
		return fmt.Errorf("Key permissions setting failed: %w", err)
	}
	if err := keyctl.Link(keyring, key); err != nil {
		return fmt.Errorf("Key link failed: %w", err)
	}
	if err := keyctl.Unlink(session, key); err != nil {
		return fmt.Errorf("Key unlink failed: %w", err)
	}

	// TODO - do we need to also copy the manifestCA.pem out of initrd?

	return nil
}
