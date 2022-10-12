package lib

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/pkg/errors"

	tpm2 "github.com/canonical/go-tpm2"
	tlinux "github.com/canonical/go-tpm2/linux"
	tutil "github.com/canonical/go-tpm2/util"
	templates "github.com/canonical/go-tpm2/templates"
)

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
}

func NewTpm2() *tpm2Trust {
	t := tpm2Trust{}
	return &t
}

func ChooseSignData() (string, string, error) {
	return "", "", nil
}

func loadPubkey(tpm *tpm2.TPMContext, dataDir, keyClass, poltype string) (tpm2.ResourceContext, error) {
	// pubkeys are stored under grandparent of datadir
	p := filepath.Dir(filepath.Dir(dataDir))
	fname := fmt.Sprintf("%s-%s.pem", poltype, keyClass)
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
			templates.KeyUsageDecrypt,
			nil,
			pub.(*rsa.PublicKey))
	return tpm.LoadExternal(nil, public, tpm2.HandleOwner)

}

func (t *tpm2Trust) Provision(certPath, keyPath string) error {
	dataDir, keyClass, err := ChooseSignData()
	if err != nil {
		return err
	}
	log.Infof("Signdata: keyclass %s datadir %s", keyClass, dataDir)

	tcti, err := tlinux.OpenDevice("/dev/tpm0")
	if err != nil {
		log.Errorf("Error opening tpm device: %v", err)
		os.Exit(1)
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	log.Infof("Taking ownership of TPM.")
	type namedContext struct {
		name      string
		resource  tpm2.ResourceContext
	}
	contexts := []namedContext{
		namedContext{name: "null", resource: tpm.NullHandleContext()},
		namedContext{name: "platform", resource: tpm.PlatformHandleContext()},
		namedContext{name: "lockout", resource: tpm.LockoutHandleContext()},
		namedContext{name: "owner", resource: tpm.OwnerHandleContext()},
	}
	cleared := false
	for _, c := range contexts {
		err := tpm.Clear(c.resource, nil)
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

	tpmPass, err := genPassphrase()
	if err != nil {
		return err
	}

	// Admin password on some hardware can't be longer than 32.
	tpmPass = tpmPass[:31]

	// TODO - save only if debug requested?
	err = os.WriteFile("/run/tpm-passphrase", []byte(tpmPass), 0600)
	if err != nil {
		log.Warnf("Unable to save admin passphrase in backup file")
	}

	pk, err := loadPubkey(tpm, dataDir, keyClass, "tpmpass")
	if err != nil {
		return err
	}

	sess, err := tpm.StartAuthSession(pk, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return err
	}

	err = tpm.PolicyAuthorize(sess, tpm2.Digest{}, tpm2.Nonce{}, pk.Name(), nil)
	if err != nil {
		return errors.Wrapf(err, "Failed authorizing trial policy for tpm admin password")
	}

	nvpub := tpm2.NVPublic{
		Index: 0x1500001,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVOwnerRead),
		AuthPolicy: tpm2.Digest{},
		Size: 8,
	}

	_, err = tpm.NVDefineSpace(pk, tpm2.HandleOwner, nil, nvpub)
	if err != nil {
		return errors.Wrapf(err, "Failed defining tpm password nvindex")
	}

	return errors.Errorf("Not yet implemented")
}

func (t *tpm2Trust) InitrdSetup() error {
	return errors.Errorf("Not yet implemented")
}

func (t *tpm2Trust) PreInstall() error {
	return errors.Errorf("Not yet implemented")
}

// these are for debugging
func (t *tpm2Trust) TpmLayoutVersion() (string, error) {
	tcti, err := tlinux.OpenDevice("/dev/tpm0")
	if err != nil {
		log.Errorf("Error opening tpm device: %v", err)
		os.Exit(1)
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	// Read the layout version
	index, err := tpm.CreateResourceContextFromTPM(tpm2.Handle(TPM2IndexTPMVersion))
	if err != nil {
		log.Errorf("Error creating resource")
		os.Exit(1)
	}
	data, err := tpm.NVRead(index, index, 8, 0, nil)
	return string(data), err
}

func (t *tpm2Trust) TpmEAVersion() (string, error) {
	tcti, err := tlinux.OpenDevice("/dev/tpm0")
	if err != nil {
		log.Errorf("Error opening tpm device: %v", err)
		os.Exit(1)
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	// Read the layout version
	index, err := tpm.CreateResourceContextFromTPM(tpm2.Handle(TPM2IndexEAVersion))
	if err != nil {
		log.Errorf("Error creating resource")
		os.Exit(1)
	}
	data, err := tpm.NVRead(index, index, 4, 0, nil)
	return string(data), err
}
