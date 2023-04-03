package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/go-git/go-git/v5"
	"github.com/google/uuid"
	"github.com/urfave/cli"
)

func generaterootCA(destdir string, caTemplate *x509.Certificate, doguid bool) error {
	// Generate keypair
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	err = privkey.Validate()
	if err != nil {
		return err
	}

	// Include a serial number and generate self-signed certificate
	serialNo, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	caTemplate.SerialNumber = serialNo

	rootCA, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privkey.PublicKey, privkey)
	if err != nil {
		return err
	}
	// Save the private key and cert to the specified directory
	defer func() {
		if err != nil {
			os.Remove(filepath.Join(destdir, "privkey.pem"))
			os.Remove(filepath.Join(destdir, "cert.pem"))
		}
	}()

	keyPEM, err := os.Create(filepath.Join(destdir, "privkey.pem"))
	if err != nil {
		return err
	}
	defer keyPEM.Close()

	pkcs8, err := x509.MarshalPKCS8PrivateKey(privkey)
	if err != nil {
		return err
	}
	err = pem.Encode(keyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err != nil {
		return err
	}
	err = os.Chmod(filepath.Join(destdir, "privkey.pem"), 0600)
	if err != nil {
		return err
	}

	// Save signed certificate
	certPEM, err := os.Create(filepath.Join(destdir, "cert.pem"))
	if err != nil {
		return err
	}
	defer certPEM.Close()

	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: rootCA})
	if err != nil {
		return err
	}
	err = os.Chmod(filepath.Join(destdir, "cert.pem"), 0640)
	if err != nil {
		return err
	}

	// Is a guid needed...
	if doguid {
		guid := uuid.NewString()
		err = os.WriteFile(filepath.Join(destdir, "guid"), []byte(guid), 0640)
		if err != nil {
			return err
		}
	}

	return nil
}

// Generates an RSA 2048 keypair, self-signed cert and a guid if specified.
func generateCreds(destdir string, doguid bool, template *x509.Certificate) error {
	// Generate keypair
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	err = privkey.Validate()
	if err != nil {
		return err
	}

	// Add additional info to certificate
	serialNo, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template.SerialNumber = serialNo
	// SubjectKeyID is sha1 hash of the public key
	pubKey := privkey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return err
	}
	subjectKeyID := sha1.Sum(publicKeyBytes)
	template.SubjectKeyId = subjectKeyID[:]

	newcert, err := x509.CreateCertificate(rand.Reader, template, template, &privkey.PublicKey, privkey)
	if err != nil {
		return err
	}

	// Save the private key and cert to the specified directory
	defer func() {
		if err != nil {
			os.Remove(filepath.Join(destdir, "privkey.pem"))
			os.Remove(filepath.Join(destdir, "cert.pem"))
		}
	}()
	keyPEM, err := os.Create(filepath.Join(destdir, "privkey.pem"))
	if err != nil {
		return err
	}
	defer keyPEM.Close()

	pkcs8, err := x509.MarshalPKCS8PrivateKey(privkey)
	if err != nil {
		return err
	}
	err = pem.Encode(keyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err != nil {
		return err
	}
	err = os.Chmod(filepath.Join(destdir, "privkey.pem"), 0600)
	if err != nil {
		return err
	}

	// Save signed certificate
	certPEM, err := os.Create(filepath.Join(destdir, "cert.pem"))
	if err != nil {
		return err
	}
	defer certPEM.Close()
	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: newcert})
	if err != nil {
		return err
	}
	err = os.Chmod(filepath.Join(destdir, "cert.pem"), 0640)
	if err != nil {
		return err
	}

	// Is a guid needed...
	if doguid {
		guid := uuid.NewString()
		err = os.WriteFile(filepath.Join(destdir, "guid"), []byte(guid), 0640)
		if err != nil {
			return err
		}
	}

	return nil
}

func generateMosCreds(keysetPath string, ctemplate *x509.Certificate) error {
	type AddCertInfo struct {
		cn     string
		doguid bool
	}
	keyinfo := map[string]AddCertInfo{
		"tpmpol-admin":   AddCertInfo{"TPM EAPolicy Admin", false},
		"tpmpol-luks":    AddCertInfo{"TPM EAPolicy LUKS", false},
		"uki-tpm":        AddCertInfo{"UKI TPM", true},
		"uki-limited":    AddCertInfo{"UKI Limited", true},
		"uki-production": AddCertInfo{"UKI Production", true},
		"uefi-db":        AddCertInfo{"UEFI DB", true},
	}

	for key, CertInfo := range keyinfo {
		ctemplate.Subject.CommonName = CertInfo.cn
		err := generateCreds(filepath.Join(keysetPath, key), CertInfo.doguid, ctemplate)
		if err != nil {
			return err
		}
	}
	return nil
}

func makeKeydirs(keysetPath string) error {
	keyDirs := []string{"manifest-ca", "manifest", "sudi-ca", "tpmpol-admin", "tpmpol-luks", "uefi-db", "uki-limited", "uki-production", "uki-tpm", "pk", "kek"}
	err := os.MkdirAll(keysetPath, 0750)
	if err != nil {
		return err
	}

	for _, dir := range keyDirs {
		err = os.Mkdir(filepath.Join(keysetPath, dir), 0750)
		if err != nil {
			return err
		}
	}
	return nil
}

func initkeyset(keysetName string, Org []string) error {
	var caTemplate, certTemplate x509.Certificate
	const (
		doGUID = true
		noGUID = false
	)
	if keysetName == "" {
		return errors.New("keyset parameter is missing")
	}

	moskeysetPath, err := getMosKeyPath()
	if err != nil {
		return err
	}
	keysetPath := filepath.Join(moskeysetPath, keysetName)
	if PathExists(keysetPath) {
		return fmt.Errorf("%s keyset already exists", keysetName)
	}

	os.MkdirAll(keysetPath, 0750)

	// Start generating the new keys
	defer func() {
		if err != nil {
			os.RemoveAll(keysetPath)
		}
	}()

	err = makeKeydirs(keysetPath)
	if err != nil {
		return err
	}

	// Prepare certificate template

	//OU := fmt.Sprintf("PuzzlesOS Machine Project %s", keysetName)
	caTemplate.Subject.Organization = Org
	caTemplate.Subject.OrganizationalUnit = []string{"PuzzlesOS Machine Project " + keysetName}
	caTemplate.Subject.CommonName = "Manifest rootCA"
	caTemplate.NotBefore = time.Now()
	caTemplate.NotAfter = time.Now().AddDate(25, 0, 0)
	caTemplate.IsCA = true
	caTemplate.BasicConstraintsValid = true

	// Generate the manifest rootCA
	err = generaterootCA(filepath.Join(keysetPath, "manifest-ca"), &caTemplate, noGUID)
	if err != nil {
		return err
	}

	// Generate the sudi rootCA
	caTemplate.Subject.CommonName = "SUDI rootCA"
	caTemplate.NotAfter = time.Date(2099, time.December, 31, 23, 0, 0, 0, time.UTC)
	err = generaterootCA(filepath.Join(keysetPath, "sudi-ca"), &caTemplate, noGUID)
	if err != nil {
		return err
	}

	// Generate PK
	caTemplate.Subject.CommonName = "UEFI PK"
	caTemplate.NotAfter = time.Now().AddDate(50, 0, 0)
	err = generaterootCA(filepath.Join(keysetPath, "pk"), &caTemplate, doGUID)
	if err != nil {
		return err
	}

	// Generate additional MOS credentials
	certTemplate.Subject.Organization = Org
	certTemplate.Subject.OrganizationalUnit = []string{"PuzzlesOS Machine Project " + keysetName}
	certTemplate.NotBefore = time.Now()
	certTemplate.NotAfter = time.Now().AddDate(25, 0, 0)
	certTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}

	err = generateMosCreds(keysetPath, &certTemplate)
	if err != nil {
		return err
	}

	// Generate KEK, signed by PK
	CAcert, CAprivkey, err := getCA("pk", keysetName)
	if err != nil {
		return err
	}
	// reuse certTemplate with some modifications
	certTemplate.Subject.CommonName = "UEFI KEK"
	certTemplate.NotAfter = time.Now().AddDate(50, 0, 0)
	certTemplate.ExtKeyUsage = nil
	err = SignCert(&certTemplate, CAcert, CAprivkey, filepath.Join(keysetPath, "kek"))
	if err != nil {
		return err
	}
	guid := uuid.NewString()
	err = os.WriteFile(filepath.Join(keysetPath, "kek", "guid"), []byte(guid), 0640)
	if err != nil {
		return err
	}

	// Generate sample uuid, manifest key and cert
	err = generateNewUUIDCreds(keysetName, filepath.Join(keysetPath, "manifest"))
	if err != nil {
		return err
	}

	// TODO: Generate new manifest cert

	// TODO: Generate new sudi certs for VMs
	return nil
}

var initKeysetCmd = cli.Command{
	Name:  "initkeyset",
	Usage: "Generate keyset for MOS",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "keysetname",
			Usage: "Name of the keyset to use for mos.",
		},
		cli.StringSliceFlag{
			Name:  "Org",
			Usage: "X509-Organization field to add to certificates when generating a new keysey. (optional)",
		},
	},
	Action: doInitKeyset,
}

func doInitKeyset(ctx *cli.Context) error {
	keysetName := ctx.String("keysetname")
	Org := ctx.StringSlice("Org")

	if keysetName == "" {
		return errors.New("Please specify keysetname")
	}

	if Org == nil {
		log.Warnf("X509-Organization field not specified for new certificates.")
	}

	// See if keyset exists
	mosKeyPath, err := getMosKeyPath()
	if err != nil {
		return err
	}
	keysetPath := filepath.Join(mosKeyPath, keysetName)
	if PathExists(keysetPath) {
		return fmt.Errorf("%s keyset already exists", keysetName)
	}

	// git clone if keyset is snakeoil
	if keysetName == "snakeoil" {
		_, err = git.PlainClone(keysetPath, false, &git.CloneOptions{URL: "https://github.com/project-machine/keys.git"})
		if err != nil {
			os.Remove(keysetPath)
			return err
		}
		return nil
	}
	// Otherwise, generate a new keyset
	return initkeyset(keysetName, Org)
}
