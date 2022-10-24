package lib

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
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

func readHostPcr7() ([]byte, error) {
	f, err := ioutil.TempFile("/tmp", "pcr")
	if err != nil {
		return []byte{}, err
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)
	cmd := []string{"tpm2_pcrread", "sha256:7", "-o", name}
	env := []string{"TPM2TOOLS_TCTI=device:/dev/tpm0"}
	err = runEnv(cmd, env)
	if err != nil {
		return []byte{}, err
	}
	contents, err := ioutil.ReadFile(name)
	return contents, err
}

func curPcr7() (string, error) {
	c, err := readHostPcr7()
	if err != nil {
		return "", fmt.Errorf("Error reading host pcr7: %w", err)
	}
	if nativeEndian == binary.LittleEndian {
		for start := 0; start+1 < len(c); start += 2 {
			tmp := c[start]
			c[start] = c[start+1]
			c[start+1] = tmp
		}
	}
	ret := ""
	for _, x := range c {
		ret = ret + fmt.Sprintf("%02x", x)
	}
	return ret, nil
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

const (
	optHierarchyOwner    = "--hierarchy=o"
	optHierarchyPlatform = "--hierarchy=p"
	optHierarchyNone     = "--hierarchy=n"
	optInputStdin        = "--input=-"
)

func (c *tpm2V3Context) Tpm2FlushContext() {
	if c.sessionFile == "" {
		return
	}
	run("tpm2_flushcontext", c.sessionFile)
	os.Remove(c.sessionFile)
	c.sessionFile = ""
	if c.Keyctx != "" {
		os.Remove(c.Keyctx)
		c.Keyctx = ""
	}
}

func (c *tpm2V3Context) TempFile() *os.File {
	f, err := ioutil.TempFile(c.tmpDir, "")
	if err != nil {
		log.Fatalf("Failed to create a tmpfile in %s", c.tmpDir)
	}
	return f
}

func (c *tpm2V3Context) Tpm2LoadExternal(pubkeyPath string) error {
	f := c.TempFile()
	c.pubkeyContext = f.Name()
	f.Close()

	pkf := c.TempFile()
	c.pubkeyName = pkf.Name()
	pkf.Close()

	return run("tpm2_loadexternal", optHierarchyOwner,
		"--key-algorithm=rsa", "--public="+pubkeyPath, "--key-context="+c.pubkeyContext, "--name="+c.pubkeyName)
}

func Tpm2NVIndexLength(nvindex NVIndex) (int, error) {
	log.Debugf("Tpm2NVIndexLength(nvindex=%s)\n", nvindex.String())
	stdout, stderr, rc := runCapture("tpm2_nvreadpublic", nvindex.String())
	if rc != 0 {
		return 0, fmt.Errorf("Reading index %s failed:\nstderr: %s\nstdout: %s\n", nvindex, stderr, stdout)
	}
	// 0x1500030:
	//   name: 000b26e01e73e4f489024a06a3687b4621e4d4f2ce865f78d656d8b6c2d06b322f86
	//   hash algorithm:
	//     friendly: sha256
	//     value: 0xB
	//   attributes:
	//     friendly: ownerwrite|ownerread|policyread|written
	//     value: 0x2000A20
	//   size: 40
	//   authorization policy: 56E6476B16D9833592FF236C6E35AE7B7991535DBC83CEE6B30D404E246C29A6
	var re = regexp.MustCompile(`(?m)size:\s(?P<Size>\d+)`)

	matches := re.FindAll(stdout, -1)
	if len(matches) != 1 {
		return 0, fmt.Errorf("Didn't find size field in stdout: %s\n", stdout)
	}

	var size int
	_, err := fmt.Sscanf(string(matches[0]), "size: %d", &size)
	if err != nil {
		return 0, fmt.Errorf("Failed to parse size field from: %s\n", matches[0])
	}

	return size, nil
}
func (c *tpm2V3Context) Tpm2CreatePrimary() (error) {
	log.Debugf("Tpm2CreatePrimary")
	if c.Keyctx != "" {
		log.Debugf("Tpm2CreatePrimary: a primary context already exists (%s), reusing it", c.Keyctx)
		return nil
	}

	f := c.TempFile()
	fname := f.Name()
	f.Close()

	cmd := []string{"tpm2_createprimary", "--key-context="+fname}
	if c.adminPwd != "" { // provisioning
		cmd = append(cmd, optHierarchyOwner, "--hierarchy-auth=" + c.adminPwd)
	} else {
		// reading
		cmd = append(cmd, optHierarchyNone)
	}

	if err := run(cmd...); err != nil {
		return fmt.Errorf("Error creating primary: %w", err)
	}
	c.Keyctx = fname
	return nil
}


type TrialPolicy bool

const (
	PolicySession TrialPolicy = false
	TrialSession              = true
)

func (c *tpm2V3Context) Tpm2StartSession(isTrial TrialPolicy) error {
	if !isTrial {
		if err := c.Tpm2CreatePrimary(); err != nil {
			return fmt.Errorf("Failed creating primary: %w", err)
		}
	} else {
		c.Keyctx = ""
	}

	f := c.TempFile()
	c.sessionFile = f.Name()
	f.Close()

	cmd := []string{
		"tpm2_startauthsession", "--session=" + c.sessionFile,
	}

	if c.Keyctx != "" {
		cmd = append(cmd, "--key-context="+c.Keyctx)
	}
	if !isTrial {
		cmd = append(cmd, "--policy-session")
	}

	return run(cmd...)
}


func (c *tpm2V3Context) Tpm2PolicyPCR(pcrs string) error {
	return run("tpm2_policypcr", "--session="+c.sessionFile, "--pcr-list="+pcrs)
}

func (c *tpm2V3Context) Tpm2Read(nvindex NVIndex, size int) (string, error) {
	cmd := []string{
		"tpm2_nvread",
		optHierarchyOwner,
		fmt.Sprintf("--size=%d", size),
		nvindex.String(),
	}
	if c.adminPwd != "" {
		cmd = append(cmd, "--auth="+c.adminPwd)
	} else {
		cmd = append(cmd, "--auth=session:"+c.sessionFile)
	}

	stdout, stderr, rc := runCapture(cmd...)
	if rc != 0 {
		return "", fmt.Errorf("Reading %d bytes at index %s failed:\nstderr: %s\nstdout: %s\n",
			size, nvindex, stderr, stdout)
	}
	return string(stdout), nil
}

func (c *tpm2V3Context) Tpm2NVWriteAsAdmin(nvindex NVIndex, towrite string) error {
	cmd := []string{"tpm2_nvwrite", optHierarchyOwner, "--auth=" + c.adminPwd, optInputStdin, nvindex.String()}
	stdout, stderr, rc := runCaptureStdin(towrite, cmd...)
	if rc != 0 {
		return fmt.Errorf("Failed running %s [%d]\nError: %s\nOutput: %s\n", cmd, rc, stderr, stdout)
	}
	return nil
}

func (c *tpm2V3Context) Tpm2NVWriteWithPolicy(nvindex NVIndex, towrite string) error {
	signedPolicyPath := filepath.Join(c.dataDir, "tpm_luks.policy.signed")

	pubkeyPath := c.Pubkeypath("luks")
	err := c.Tpm2LoadExternal(pubkeyPath)
	if err != nil {
		return fmt.Errorf("Failed loading public key: %s: %w", pubkeyPath, err)
	}

	err = c.Tpm2StartSession(PolicySession)
	if err != nil {
		return fmt.Errorf("Failed creating auth session: %w", err)
	}
	defer c.Tpm2FlushContext()

	err = c.Tpm2PolicyPCR(TPM_PCRS_DEF)
	if err != nil {
		return fmt.Errorf("Failed to create PCR Policy event with TPM: %w", err)
	}

	policyVersionSize := 4
	policyVersion, err := Tpm2Read(TPM2IndexEAVersion, policyVersionSize)
	if err != nil {
		return fmt.Errorf("Failed to read PolicyVersion: %w", err)
	}

	policyDigest, err := c.Tpm2PolicyNV(policyVersion)
	if err != nil {
		return fmt.Errorf("The policy version specified does not match contents of TPM NV Index: %w", err)
	}

	ticket, err := c.Tpm2VerifySignature(c.pubkeyContext, policyDigest, signedPolicyPath)
	if err != nil {
		return fmt.Errorf("Failed to verify signature on EA Policy: %s: %w", signedPolicyPath, err)
	}

	// tpm2_policyauthorize
	_, err = c.Tpm2PolicyAuthorizeTicket(policyDigest, ticket)
	if err != nil {
		return fmt.Errorf("Failed to Authorize the EA Policy, invalid signature on the policy digest: %w", err)
	}

	cmd := []string{
		"tpm2_nvwrite",
		fmt.Sprintf("--auth=session:%s", c.sessionFile),
		optInputStdin,
		nvindex.String(),
	}
	stdout, stderr, rc := runCaptureStdin(towrite, cmd...)
	if rc != 0 {
		return fmt.Errorf("Failed running %s [%d]\nError: %s\nOutput: %s\n", cmd, rc, stderr, stdout)
	}

	return nil
}

func (c *tpm2V3Context) Tpm2PolicyNV(towrite string) (string, error) {
	f := c.TempFile()
	fname := f.Name()
	f.Close()

	cmd := []string{"tpm2_policynv", "--session=" + c.sessionFile, optInputStdin, TPM2IndexEAVersion.String(), "eq", "--policy=" + fname}
	stdout, stderr, rc := runCaptureStdin(towrite, cmd...)
	if rc != 0 {
		return "", fmt.Errorf("Failed running %s [%d]\nError: %s\nOutput: %s\n", cmd, rc, stderr, stdout)
	}
	return fname, nil
}

func Tpm2Clear() error {
	// Note: long flag for -c (--auth-hierarchy) does not work with tpm2-tools 4.1.1
	err := run("tpm2_clear", "-c", "p")
	if err != nil {
		err = run("tpm2_clear")
		if err != nil {
			return fmt.Errorf("Error runnign tpm2_clear: %w", err)
		}
	}
	err = run("tpm2_dictionarylockout", "--setup-parameters", "--lockout-recovery-time=120", "--max-tries=4294967295", "--clear-lockout")
	if err != nil {
		return fmt.Errorf("Error setting lockout parameters: %w", err)
	}
	return nil
}
// Write a value which is publically readable but only writeable with tpm admin pass
func (c *tpm2V3Context) StorePublic(idx NVIndex, value string) error {
	attributes := "ownerwrite|ownerread|authread"
	err := c.Tpm2NVDefine("", attributes, idx, len(value))
	if err != nil {
		return err
	}

	return c.Tpm2NVWriteAsAdmin(idx, value)
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

func getTpmBufsize() (int, error) {
	out, rc := RunCommandWithRc("tpm2_getcap", "properties-fixed")
	if rc != 0 {
		return 0, fmt.Errorf("error %d", rc)
	}
	inSection := false
	for _, line := range strings.Split(string(out), "\n") {
		if !inSection {
			if strings.HasPrefix(line, "TPM2_PT_NV_BUFFER_MAX:") {
				inSection = true
			}
			continue
		}
		if line[0] != ' ' {
			return 0, fmt.Errorf("No TPM2_PT_NV_BUFFER_MAX value found")
		}
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "raw:") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 2 {
			continue
		}
		word := strings.TrimSpace(fields[1])
		v, err := strconv.ParseInt(word, 0, 32)
		if err != nil {
			return -1, fmt.Errorf("strconv on %v returned error: %w", line[4:], err)
		}
		return int(v), nil
	}
	return 0, fmt.Errorf("No TPM2_PT_NV_BUFFER_MAX found")
}

func (c *tpm2V3Context) Tpm2PolicyAuthorize() (string, error) {
	f := c.TempFile()
	digestFile := f.Name()
	f.Close()

	cmd := []string{"tpm2_policyauthorize",
		"--session=" + c.sessionFile,
		"--name=" + c.pubkeyName,
		"--policy=" + digestFile}
	return digestFile, run(cmd...)
}

func (c *tpm2V3Context) Tpm2PolicyAuthorizeTicket(policyDigest, ticketFile string) (string, error) {
	log.Debugf("Tpm2PolicyAuthorizeTicket(session=%s policyDigest=%s ticketFile=%s)\n", c.sessionFile, policyDigest, ticketFile)
	f := c.TempFile()
	digestFile := f.Name()
	f.Close()

	cmd := []string{"tpm2_policyauthorize", "-S", c.sessionFile, "-i", policyDigest, "-n", c.pubkeyName, "-t", ticketFile}
	return digestFile, run(cmd...)
}

func Tpm2Read(nvindex NVIndex, size int) (string, error) {
	log.Debugf("Tpm2Read(nvindex=%s size=%d)\n", nvindex.String(), size)
	stdout, stderr, rc := RunCommandWithOutputErrorRc("tpm2_nvread", "-s", fmt.Sprintf("%d", size), nvindex.String())
	if rc != 0 {
		return "", fmt.Errorf("Reading %d bytes at index %s failed:\nstderr: %s\nstdout: %s\n",
			size, nvindex, stderr, stdout)
	}
	return string(stdout), nil
}

func (c *tpm2V3Context) Tpm2VerifySignature(pubkeyContextFile, digestFile, signatureFile string) (string, error) {
	log.Debugf("Tpm2VerifySignature(pubkeyContext=%s digestFile=%s sigFile=%s)\n", pubkeyContextFile, digestFile, signatureFile)
	scheme := "rsassa"
	hashAlgo := "sha256"

	f := c.TempFile()
	ticketFile := f.Name()
	f.Close()

	cmd := []string{"tpm2_verifysignature", "-c", pubkeyContextFile, "-f", scheme, "-g", hashAlgo, "-m", digestFile, "-s", signatureFile, "-t", ticketFile}
	return ticketFile, run(cmd...)
}

func (c *tpm2V3Context) Tpm2ReadSession(nvindex NVIndex, offset int, size int) (string, error) {
	log.Debugf("Tpm2ReadSession(session=%s nvindex=%s size=%d)\n", c.sessionFile, nvindex.String(), size)
	cmd := []string{
		"tpm2_nvread",
		fmt.Sprintf("--auth=session:%s", c.sessionFile),
		fmt.Sprintf("--size=%d", size),
		fmt.Sprintf("--offset=%d", offset),
		nvindex.String(),
	}

	stdout, stderr, rc := RunCommandWithOutputErrorRc(cmd...)
	if rc != 0 {
		return "", fmt.Errorf("Reading %d bytes at index %s failed:\nstderr: %s\nstdout: %s\n",
			size, nvindex, stderr, stdout)
	}
	return string(stdout), nil
}

func (c *tpm2V3Context) ReadSecretPiece(idx NVIndex, signedPolicyPath string, offset int, size int) (string, error) {
	err := c.Tpm2StartSession(PolicySession)
	if err != nil {
		return "", fmt.Errorf("Failed creating auth session: %w", err)
	}
	defer c.Tpm2FlushContext()

	err = c.Tpm2PolicyPCR(TPM_PCRS_DEF)
	if err != nil {
		return "", fmt.Errorf("Failed to create PCR Policy event with TPM: %w", err)
	}

	policyVersionSize := 4
	policyVersion, err := Tpm2Read(TPM2IndexEAVersion, policyVersionSize)
	if err != nil {
		return "", fmt.Errorf("Failed to read PolicyVersion: %w", err)
	}

	log.Debugf("tpm2V3Context.ReadSecretPiece() PolicyNVDigest\n")
	policyDigest, err := c.Tpm2PolicyNV(policyVersion)
	if err != nil {
		return "", fmt.Errorf("The policy version specified does not match contents of TPM NV Index: %w", err)
	}

	log.Debugf("tpm2V3Context.ReadSecretPiece() VerifySignature\n")
	ticket, err := c.Tpm2VerifySignature(c.pubkeyContext, policyDigest, signedPolicyPath)
	if err != nil {
		return "", fmt.Errorf("Failed to verify signature on EA Policy: %s: %w", signedPolicyPath, err)
	}

	// tpm2_policyauthorize
	log.Debugf("tpm2V3Context.ReadSecretPiece() PolicyAuthorize\n")
	_, err = c.Tpm2PolicyAuthorizeTicket(policyDigest, ticket)
	if err != nil {
		return "", fmt.Errorf("Failed to Authorize the EA Policy, invalid signature on the policy digest: %w", err)
	}

	// tpm2_nvread
	log.Debugf("tpm2V3Context.ReadSecretPiece() ReadSession\n")
	secret, err := c.Tpm2ReadSession(idx, offset, size)
	if err != nil {
		return "", fmt.Errorf("Failed to read Secret from TPM: %w", err)
	}

	return secret, nil
}

func (c *tpm2V3Context) ReadSecret(idx NVIndex, signedPolicyPath string) (string, error) {
	log.Debugf("tpm2V3Context.ReadSecret(signed policy=%s)\n", signedPolicyPath)
	bufsize, err := getTpmBufsize()
	if err != nil {
		return "", err
	}
	secretLength, err := Tpm2NVIndexLength(idx)
	if err != nil {
		return "", fmt.Errorf("Failed to obtain length of NV index %s: %w", idx, err)
	}

	log.Debugf("tpm2V3Context.ReadSecret() loadExternal\n")
	pubkeyPath := c.Pubkeypath("luks")
	err = c.Tpm2LoadExternal(pubkeyPath)
	if err != nil {
		return "", fmt.Errorf("Failed loading public key: %s: %w", pubkeyPath, err)
	}

	log.Debugf("reading %s, got bufsize %d secretlength %d", idx, bufsize, secretLength)
	whole := ""
	offset := 0
	for secretLength > 0 {
		copySize := secretLength
		if copySize > bufsize {
			copySize = bufsize
		}
		log.Debugf("reading %d bytes at offset %d", copySize, offset)
		piece, err := c.ReadSecretPiece(idx, signedPolicyPath, offset, copySize)
		if err != nil {
			return "", fmt.Errorf("Reading offset %d size %d of %s returned error : %w", offset, copySize, idx, err)
		}
		whole = whole + piece
		secretLength -= copySize
		offset += copySize
	}

	return whole, nil
}

func (c *tpm2V3Context) Tpm2NVDefine(digestfile string, attr string, index NVIndex, l int) error {
	length := fmt.Sprintf("%d", l)
	cmd := []string{"tpm2_nvdefine", "--attributes=" + attr, "--hierarchy-auth=" + c.adminPwd}
	if digestfile != "" {
		cmd = append(cmd, "--policy="+digestfile)
	}
	cmd = append(cmd, "--size="+length, index.String())
	return run(cmd...)
}

// Store the TPM password.  This is a lot more than that, though:
// 1. load the public signing key into the TPM
// 2. load the EA policy to protect the password
func (c *tpm2V3Context) StoreAdminPassword() error {
	contexts := []string{"owner", "endorsement", "lockout"}
	for _, context := range contexts {
		err := run("tpm2_changeauth", "--object-context="+context, c.adminPwd)
		if err != nil {
			return err
		}
	}

	pubkeyPath := c.Pubkeypath("tpmpass")
	err := c.Tpm2LoadExternal(pubkeyPath)
	if err != nil {
		return fmt.Errorf("Failed loading tpm-passwd policy public key: %w", err)
	}

	err = c.Tpm2StartSession(TrialSession)
	if err != nil {
		return fmt.Errorf("Failed creating trial auth session: %w", err)
	}
	policyDigestFile, err := c.Tpm2PolicyAuthorize()
	if err != nil {
		return fmt.Errorf("Failed authorizing PCR policy: %w", err)
	}

	attributes := "ownerwrite|ownerread|policyread"
	err = c.Tpm2NVDefine(policyDigestFile, attributes, TPM2IndexPassword, len(c.adminPwd))
	if err != nil {
		return fmt.Errorf("Failed defining NV: %w", err)
	}
	c.Tpm2FlushContext()

	err = c.Tpm2NVWriteAsAdmin(TPM2IndexPassword, c.adminPwd)
	if err != nil {
		return fmt.Errorf("Failed writing TPM passphrase to TPM: %w", err)
	}

	return nil
}

// echo atomix | sha256sum
const atxSha = "b7135cbb321a66fa848b07288bd008b89bd5b7496c4569c5e1a4efd5f7c8e0a7"

func (t *tpm2V3Context) ExtendPCR7() error {
	cmd := []string{"tpm2_pcrextend", "7:sha256=" + atxSha}
	return run(cmd...)
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
