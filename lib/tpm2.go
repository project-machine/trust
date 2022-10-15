package lib

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/apex/log"
	"github.com/pkg/errors"

	tpm2 "github.com/canonical/go-tpm2"
	tlinux "github.com/canonical/go-tpm2/linux"
	tutil "github.com/canonical/go-tpm2/util"
	templates "github.com/canonical/go-tpm2/templates"
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

func HWRNGRead(size int) ([]byte, error) {
        rf, err := os.Open("/dev/hwrng")
        if err != nil {
                return []byte{}, err
        }
        defer rf.Close()
        buf := make([]byte, size)
        num, err := rf.Read(buf)
        if err != nil {
                return []byte{}, err
        }

        if num != size {
                return []byte(buf), fmt.Errorf("Read only %d bytes, wanted %d", num, size)
        }

        return []byte(buf), nil
}

func genPassphrase() (string, error) {
	rand, err := HWRNGRead(16)
	if err != nil {
		return "", err
	}
	return ("trust-" + hex.EncodeToString(rand)), nil
}

type tpm2Trust struct {
	// During provisioning
	adminPwd string
	keyClass string
	dataDir  string
	tpm      *tpm2.TPMContext
	pubkeys  map[string]tpm2.ResourceContext

}

func NewTpm2() *tpm2Trust {
	t := tpm2Trust{}
	t.pubkeys = make(map[string]tpm2.ResourceContext)
	tcti, err := tlinux.OpenDevice("/dev/tpm0")
	if err != nil {
		log.Errorf("Error opening tpm device: %v", err)
		os.Exit(1)
	}
	tpm := tpm2.NewTPMContext(tcti)
	t.tpm = tpm
	err = t.EnsurePCR7Data()
	if err != nil {
		log.Warnf("Failed finding pcr7 data: %v", err)
	}

	return &t
}

func (t *tpm2Trust) Close() {
	t.tpm.Close()
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

func (t *tpm2Trust)readHostPcr7() ([]byte, error) {
	pcrSel := tpm2.PCRSelection{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}
	pcrList := []tpm2.PCRSelection{pcrSel}
	_, v, err := t.tpm.PCRRead(pcrList)
	if err != nil {
		return []byte{}, errors.Wrapf(err, "Failed reading pcr7")
	}
	if r, ok := v[tpm2.HashAlgorithmSHA256][7]; ok {
		log.Infof("Found PCR7 %v", r)
		return r, nil
	}
	return []byte{}, errors.Errorf("No sha256 value for pcr7 found")
}

func (t *tpm2Trust) curPCR7() (string, error) {
	c, err := t.readHostPcr7()
	if err != nil {
		return "", errors.Errorf("Error reading host pcr7: %v", err)
	}
	if len(c) == 0 {
		return "", errors.Errorf("host pcr7 was empty")
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
func (t *tpm2Trust)getPoldir(pdir string) string {
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

// Return the directory for *.bin and the key class (dev, release, or snakeoil).
// The pubkeys will come from Dir(Dir(signdata))/pubkeys/luks-${class}.pem and
// Dir(Dir(signdata))/pubkeys/tpmpass-${class}.pem and
func (t *tpm2Trust) FindPCR7Data() (string, string, error) {
	polDir := t.getPoldir("/pcr7data")
	if polDir == "" {
		return "", "", fmt.Errorf("no policy dir found")
	}
	pcr7, err := t.curPCR7()
	if err != nil {
		return "", "", err
	}
	pcr7Dir := filepath.Join(polDir, pcr7[:2], pcr7[2:])

	var info signDataInfo
	infoPath := filepath.Join(pcr7Dir, "info.json")
	infoBytes, err := ioutil.ReadFile(infoPath)
	if err != nil {
		return "", "", err
	}
	err = json.Unmarshal(infoBytes, &info)
	if err != nil {
		return "", "", err
	}

	return pcr7Dir, info.Class, nil
}


func (t *tpm2Trust)loadPubkey(poltype string, purpose templates.KeyUsage) (tpm2.ResourceContext, error) {
	// pubkeys are stored under grandparent of datadir
	p := filepath.Dir(filepath.Dir(t.dataDir))
	fname := fmt.Sprintf("%s-%s.pem", poltype, t.keyClass)
	p = filepath.Join(p, "pubkeys", fname)
	bytes, err := os.ReadFile(p)
	if err != nil {
		return nil, errors.Wrapf(err, "Error reading %s policy public key", poltype)
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.Errorf("Failed parsing PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	public := tutil.NewExternalRSAPublicKey(
			tpm2.HashAlgorithmSHA256,
			purpose,
			nil,
			pub.(*rsa.PublicKey))
	return t.tpm.LoadExternal(nil, public, tpm2.HandleOwner)

}

func (t *tpm2Trust) CreateIndex(idx NVIndex, len uint16, value []byte, attrs tpm2.NVAttributes) error {
	nvpub := tpm2.NVPublic{
		Index: tpm2.Handle(idx),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      attrs,
		Size: len,
	}

	rc, err := t.tpm.NVDefineSpace(t.tpm.OwnerHandleContext(), nil, &nvpub, nil)
	if err != nil {
		return errors.Wrapf(err, "Failed defining NVIndex %s", idx)
	}

	err = t.tpm.NVWrite(t.tpm.OwnerHandleContext(), rc, value, 0, nil)
	if err != nil {
		return errors.Wrapf(err, "Failed writing NVIndex %s", idx)
	}

	return nil
}

func (t *tpm2Trust) CreateEAIndex(idx NVIndex, l uint16, value []byte, attrs tpm2.NVAttributes) error {
	var err error
	log.Infof("writing %s length %d value %v", idx, l, value)
	pubkeyname := "luks"
	if idx == TPM2IndexPassword {
		pubkeyname = "tpmpass"
	}

	pk, ok := t.pubkeys[pubkeyname]
	if !ok {
		pk, err = t.loadPubkey(pubkeyname, templates.KeyUsageDecrypt)
		if err != nil {
			return errors.Wrapf(err, "Error loading public key")
		}
		t.pubkeys[pubkeyname] = pk
	}

	tp := tutil.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	tp.PolicyAuthorize([]byte(""), pk.Name())
	d := tp.GetDigest()

	nvpub := tpm2.NVPublic{
		Index: tpm2.Handle(idx),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      attrs,
		AuthPolicy: d,
		Size: l,
	}

	rc, err := t.tpm.NVDefineSpace(t.tpm.OwnerHandleContext(), tpm2.Auth([]byte(t.adminPwd)), &nvpub, nil)
	if err != nil {
		return errors.Wrapf(err, "Failed defining nvindex %s", idx)
	}

	err = t.tpm.NVWrite(t.tpm.OwnerHandleContext(), rc, value, 0, nil)
	if err != nil {
		return errors.Wrapf(err, "Failed writing NVIndex %s", idx)
	}

	return nil
}

func (t *tpm2Trust) EnsurePCR7Data() error {
	dataDir, keyClass, err := t.FindPCR7Data()
	if err != nil {
		return err
	}
	log.Infof("Signdata: keyclass %s datadir %s", keyClass, dataDir)
	t.keyClass = keyClass
	t.dataDir = dataDir
	return nil
}

func (t *tpm2Trust) Provision(certPath, keyPath string) error {
	// Store the provisioned cert and key
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return errors.Wrapf(err, "Failed reading provisioned certificate")
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return errors.Wrapf(err, "Failed reading provisioned key")
	}

	log.Infof("Taking ownership of TPM.")
	type namedContext struct {
		name      string
		resource  tpm2.ResourceContext
	}
	contexts := []namedContext{
		namedContext{name: "null", resource: t.tpm.NullHandleContext()},
		namedContext{name: "platform", resource: t.tpm.PlatformHandleContext()},
		namedContext{name: "lockout", resource: t.tpm.LockoutHandleContext()},
		namedContext{name: "owner", resource: t.tpm.OwnerHandleContext()},
	}
	cleared := false
	for _, c := range contexts {
		err := t.tpm.Clear(c.resource, nil)
		if err == nil {
			log.Infof("Cleared tpm using %s hierarchy", c.name)
			cleared = true
			break
		}
		log.Warnf("Error using %s hierarchy to clear tpm: %v", c.name, err)
	}
	if !cleared {
		return errors.Errorf("Failed to clear the tpm")
	}

	verStr := fmt.Sprintf("%08d", TpmLayoutVersion)
	attrs := tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead|tpm2.AttrNVOwnerWrite|tpm2.AttrNVOwnerRead)
	err = t.CreateIndex(TPM2IndexTPMVersion, uint16(len(verStr)), []byte(verStr), attrs)
	if err != nil {
		return errors.Wrapf(err, "Failed to set tpm layout version")
	}

	verStr = fmt.Sprintf("%s", PolicyVersion)
	err = t.CreateIndex(TPM2IndexEAVersion, uint16(len(verStr)), []byte(verStr), attrs)
	if err != nil {
		return errors.Wrapf(err, "Failed to set tpm EA policy version")
	}

	tpmPass, err := genPassphrase()
	if err != nil {
		return err
	}

	// Admin password on some hardware can't be longer than 32.
	tpmPass = tpmPass[:31]
	t.adminPwd = tpmPass

	// TODO - save only if debug requested?
	err = os.WriteFile("/run/tpm-passphrase", []byte(tpmPass), 0600)
	if err != nil {
		log.Warnf("Unable to save admin passphrase in backup file")
	}

	// Actually set the TPM admin password
	setPassContexts := []namedContext{
		namedContext{name: "owner", resource: t.tpm.OwnerHandleContext()},
		namedContext{name: "endorsement", resource: t.tpm.EndorsementHandleContext()},
		namedContext{name: "lockout", resource: t.tpm.LockoutHandleContext()},
	}
	for _, c := range setPassContexts {
		err = t.tpm.HierarchyChangeAuth(c.resource, []byte(tpmPass), nil)
		if err != nil {
			return errors.Wrapf(err, "Failed resetting password for %s", c.name)
		}
	}

	attrs = tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead|tpm2.AttrNVOwnerWrite|tpm2.AttrNVOwnerRead)
	b := []byte(t.adminPwd)
	err = t.CreateEAIndex(TPM2IndexPassword, 32, b, attrs)
	if err != nil {
		return errors.Wrapf(err, "Failed creating admin password nvindex")
	}

	err = t.CreateEAIndex(TPM2IndexCert, uint16(len(certBytes)), certBytes, attrs)
	if err != nil {
		return errors.Wrapf(err, "Failed writing provisioned certificate to TPM")
	}

	err = t.CreateEAIndex(TPM2IndexKey, uint16(len(keyBytes)), keyBytes, attrs)
	if err != nil {
		return errors.Wrapf(err, "Failed writing provisioned key to TPM")
	}

	// Create sbs luks passphrase
	luksPwd, err := genPassphrase()
	if err != nil {
		return err
	}
	// TODO - actually create sbf
	// Store sbf luks key
	b = []byte(luksPwd)
	err = t.CreateEAIndex(TPM2IndexSecret, uint16(len(luksPwd)), b, attrs)
	if err != nil {
		return errors.Wrapf(err, "Failed creating sbs password nvindex")
	}

	// Add policywrite to the attrs
	attrs = tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead|tpm2.AttrNVOwnerWrite|tpm2.AttrNVOwnerRead|tpm2.AttrNVPolicyWrite)
	// and write the install pwd template, which each install should overwrite
	err = t.CreateEAIndex(TPM2IndexAtxSecret, uint16(len(AtxInitialPassphrase)), []byte(AtxInitialPassphrase), attrs)
	if err != nil {
		return errors.Wrapf(err, "Failed writing the install password nvindex")
	}

	return nil
}

func (t *tpm2Trust) InitrdSetup() error {
	return errors.Errorf("Not yet implemented")
}

func (t *tpm2Trust) PreInstall() error {
	return errors.Errorf("Not yet implemented")
}

// these are for debugging
func (t *tpm2Trust) TpmLayoutVersion() (string, error) {
	// Read the layout version
	index, err := t.tpm.CreateResourceContextFromTPM(tpm2.Handle(TPM2IndexTPMVersion))
	if err != nil {
		log.Errorf("Error creating resource")
		os.Exit(1)
	}
	data, err := t.tpm.NVRead(index, index, 8, 0, nil)
	return string(data), err
}

func (t *tpm2Trust) TpmEAVersion() (string, error) {
	// Read the layout version
	index, err := t.tpm.CreateResourceContextFromTPM(tpm2.Handle(TPM2IndexEAVersion))
	if err != nil {
		log.Errorf("Error creating resource")
		os.Exit(1)
	}
	data, err := t.tpm.NVRead(index, index, 4, 0, nil)
	return string(data), err
}

func (t *tpm2Trust) readSignature(nv NVIndex) ([]byte, error) {
	filename := ""
	switch nv {
	case TPM2IndexAtxSecret, TPM2IndexSecret, TPM2IndexKey, TPM2IndexCert:
		filename = "tpm_luks.policy.signed"
	case TPM2IndexPassword: 
		filename = "tpm_passwd.policy.signed"
	}
	if filename == "" {
		return []byte{}, errors.Errorf("Invalid nvindex")
	}
	sPath := filepath.Join(t.dataDir, filename)
	bytes, err := os.ReadFile(sPath)
	if err != nil {
		return []byte{}, errors.Wrapf(err, "Error reading signed policy file %s", sPath)
	}
	return bytes, nil
}

func (t *tpm2Trust) TpmEALuks() (string, error) {
	// Read the layout version
	index, err := t.tpm.CreateResourceContextFromTPM(tpm2.Handle(TPM2IndexAtxSecret))
	if err != nil {
		log.Errorf("Error creating TPM resource for NVIndex")
		os.Exit(1)
	}

	nvp, _, err := t.tpm.NVReadPublic(index, nil)
	if err != nil {
		return "", errors.Wrapf(err, "Error getting size")
	}

	key, err := t.loadPubkey("luks", templates.KeyUsageSign)
	if err != nil {
		return "", errors.Wrapf(err, "Error loading luks policy signing key")
	}

	session, err := t.tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return "", errors.Wrapf(err, "Failed starting auth session")
	}

	err = t.tpm.PolicyPCR(session, nil,
		tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
	if err != nil {
		return "", errors.Wrapf(err, "PolicyPCR failed")
	}

	vb := []byte(PolicyVersion.String())
	nvV := tpm2.Operand(vb)

	pvIndex, err := t.tpm.CreateResourceContextFromTPM(tpm2.Handle(TPM2IndexEAVersion))
	if err != nil {
		return "", errors.Wrapf(err, "Error creating TPM resource for NVIndex")
	}
	err = t.tpm.PolicyNV(pvIndex, pvIndex, session, nvV, uint16(0), tpm2.OpEq, nil)
	if err != nil {
		return "", errors.Wrapf(err, "PolicyNV failed")
	}

	digest, err := t.tpm.PolicyGetDigest(session)
	if err != nil {
		return "", errors.Wrapf(err, "Failed getting policy digest")
	}

	s, err := t.readSignature(TPM2IndexAtxSecret)
	if err != nil {
		return "", errors.Wrapf(err, "Failed reading policy signature")
	}
	signature := tpm2.Signature{
		SigAlg:    tpm2.SigSchemeAlgRSASSA,
		Signature: &tpm2.SignatureU{RSASSA: &tpm2.SignatureRSASSA{Hash: tpm2.HashAlgorithmSHA256, Sig: s}}}
	ticket, err := t.tpm.VerifySignature(key, digest, &signature)
	if err != nil {
		return "", errors.Wrapf(err, "Failed verifying policy signature")
	}

	err = t.tpm.PolicyAuthorize(session, digest, nil, key.Name(), ticket)
	if err != nil {
		return "", err
	}

	data, err := t.tpm.NVRead(index, index, nvp.Size, 0, session)
	return string(data), err
}

func (t *tpm2Trust) ExtendPCR7() error {
	v, err := t.curPCR7()
	log.Infof("Original pcr7 value: .%s. (error %v)", v, err)

	hasher := tpm2.HashAlgorithmSHA256.NewHash()
	hasher.Write([]byte("trust"))
	hashE := tpm2.TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: hasher.Sum(nil)}
	hashList := tpm2.TaggedHashList{hashE}
	err = t.tpm.PCRExtend(t.tpm.PCRHandleContext(7), hashList, nil)
	if err != nil {
		return errors.Wrapf(err, "Failed extending pcr7")
	}

	v, err = t.curPCR7()
	log.Infof("new pcr7 value: .%s. (error %v)", v, err)
	return nil
}

func (t *tpm2Trust) TpmLuks() (string, error) {
	return "", nil
}
