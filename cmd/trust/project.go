package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/urfave/cli"
)

var newUUIDCmd = cli.Command{
	Name:  "new-uuid",
	Usage: "Generate a uuid and keypair",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "keysetname",
			Usage: "Pathname of local keys repository. (optional)",
		},
	},
	Action: doNewUUID,
}

func doNewUUID(ctx *cli.Context) error {
	keysetName := ctx.String("keysetname")
	if keysetName == "" {
		return errors.New("Please specify keysetname")
	}

	trustDir, err := getTrustPath()
	if err != nil {
		return err
	}

	destdir := filepath.Join(trustDir, "manifest")
	if !PathExists(destdir) {
		err = os.Mkdir(destdir, 0750)
		if err != nil {
			return err
		}
	} else {
		// Check if manifest credentials exist
		if PathExists(filepath.Join(destdir, "uuid")) {
			return errors.New("manifest credentials (uuid) already exist")
		}
	}

	// Create new manifest credentials
	err = generateNewUUIDCreds(keysetName, destdir)
	if err != nil {
		return err
	}
	fmt.Printf("New credentials saved in %s directory\n", destdir)
	return nil
}

// SignCert creates a CA signed certificate and keypair in destdir
func SignCert(template, CAcert *x509.Certificate, CAkey any, destdir string) error {
	// Check if credentials already exist
	if PathExists(filepath.Join(destdir, "privkey.pem")) {
		return fmt.Errorf("credentials already exist in %s", destdir)
	}

	// Save private key
	keyPEM, err := os.OpenFile(
		filepath.Join(destdir, "privkey.pem"),
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyPEM.Close()

	certPEM, err := os.OpenFile(
		filepath.Join(destdir, "cert.pem"),
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		os.Remove(keyPEM.Name())
		return err
	}
	defer certPEM.Close()

	if err := signCertToFiles(template, CAcert, CAkey, certPEM, keyPEM); err != nil {
		os.Remove(keyPEM.Name())
		os.Remove(certPEM.Name())
		return err
	}

	return nil
}

func signCertToFiles(template, CAcert *x509.Certificate, CAkey any,
	certWriter io.Writer, keyWriter io.Writer) error {
	// Generate a keypair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	err = privKey.Validate()
	if err != nil {
		return err
	}

	// Additional info to add to certificate template
	serialNo, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	// SubjectKeyID is sha1 hash of the public key
	pubKey := privKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return err
	}
	subjectKeyID := sha1.Sum(publicKeyBytes)

	template.SerialNumber = serialNo
	template.SubjectKeyId = subjectKeyID[:]

	signedCert, err := x509.CreateCertificate(rand.Reader, template, CAcert, &pubKey, CAkey)
	if err != nil {
		return err
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	err = pem.Encode(keyWriter, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err != nil {
		return err
	}

	err = pem.Encode(certWriter, &pem.Block{Type: "CERTIFICATE", Bytes: signedCert})
	if err != nil {
		return err
	}

	return nil
}

func readCertificateFromFile(CApath string) (*x509.Certificate, error) {
	// Get the rootCA cert & privKey
	certFile, err := os.ReadFile(CApath)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(certFile)
	if pemBlock == nil {
		return nil, errors.New("pem.Decode cert failed")
	}
	return x509.ParseCertificate(pemBlock.Bytes)
}

func readPrivKeyFromFile(keypath string) (any, error) {
	keyFile, err := os.ReadFile(keypath)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(keyFile)
	if pemBlock == nil {
		return nil, errors.New("pem.Decode cert failed")
	}
	return x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
}

func getCA(CAname, keysetName string) (*x509.Certificate, any, error) {
	// locate the keyset
	keysetPath, err := getMosKeyPath()
	if err != nil {
		return nil, nil, err
	}
	keysetPath = filepath.Join(keysetPath, keysetName)
	if !PathExists(keysetPath) {
		return nil, nil, fmt.Errorf("keyset %s, does not exist", keysetName)
	}

	CAcert, err := readCertificateFromFile(filepath.Join(keysetPath, CAname, "cert.pem"))
	// See if the CA exists
	CApath := filepath.Join(keysetPath, CAname)
	if !PathExists(CApath) {
		return nil, nil, fmt.Errorf("%s CA does not exist", CAname)
	}

	// Get the rootCA cert & privKey
	CAkey, err := readPrivKeyFromFile(filepath.Join(keysetPath, CAname, "privkey.pem"))

	return CAcert, CAkey, nil
}

func generateNewUUIDCreds(keysetName, destdir string) error {
	// Create new manifest credentials
	newUUID := uuid.NewString()

	// Create a certificate template
	CN := fmt.Sprintf("manifest PRODUCT:%s", newUUID)
	certTemplate := x509.Certificate{
		Subject: pkix.Name{
			CommonName: CN,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(20, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	// get CA privkey and CA cert
	CAcert, CAprivkey, err := getCA("manifest-ca", keysetName)
	if err != nil {
		return err
	}

	err = SignCert(&certTemplate, CAcert, CAprivkey, destdir)
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(destdir, "uuid"), []byte(newUUID), 0640)
	if err != nil {
		os.Remove(filepath.Join(destdir, "privkey.pem"))
		os.Remove(filepath.Join(destdir, "cert.pem"))
		return err
	}

	return nil
}
