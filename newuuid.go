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
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// SignCert reates a CA signed certificate and keypair
func SignCert(template, CAcert *x509.Certificate, CAkey any, destdir string) error {
	// Check if credentials already exist
	if PathExists(filepath.Join(destdir, "privkey.pem")) {
		return fmt.Errorf("credentials already exist in %s", destdir)
	}

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

	// Save the new key and signed certificate
	defer func() {
		if err != nil {
			os.Remove(filepath.Join(destdir, "privkey.pem"))
			os.Remove(filepath.Join(destdir, "cert.pem"))
		}
	}()

	// Save private key
	keyPEM, err := os.Create(filepath.Join(destdir, "privkey.pem"))
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	err = pem.Encode(keyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err != nil {
		return err
	}
	err = keyPEM.Close()
	if err != nil {
		return err
	}
	err = os.Chmod(filepath.Join(destdir, "privkey.pem"), 0600)
	if err != nil {
		return err
	}

	// Save signed certificate to trust dir
	certPEM, err := os.Create(filepath.Join(destdir, "cert.pem"))
	if err != nil {
		return err
	}
	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: signedCert})
	if err != nil {
		return err
	}
	err = certPEM.Close()
	if err != nil {
		return err
	}
	err = os.Chmod(filepath.Join(destdir, "cert.pem"), 0640)
	if err != nil {
		return err
	}

	return nil
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

	// See if the CA exists
	CApath := filepath.Join(keysetPath, CAname+"-ca")
	if !PathExists(CApath) {
		return nil, nil, fmt.Errorf("%s CA does not exist", CAname)
	}

	// Get the rootCA cert & privKey
	certFile, err := os.ReadFile(filepath.Join(CApath, "cert.pem"))
	if err != nil {
		return nil, nil, err
	}
	pemBlock, _ := pem.Decode(certFile)
	if pemBlock == nil {
		return nil, nil, errors.New("pem.Decode cert failed")
	}
	CAcert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyFile, err := os.ReadFile(filepath.Join(CApath, "privkey.pem"))
	if err != nil {
		return nil, nil, err
	}
	pemBlock, _ = pem.Decode(keyFile)
	if pemBlock == nil {
		return nil, nil, errors.New("pem.Decode cert failed")
	}
	CAkey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

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
	CAcert, CAprivkey, err := getCA("manifest", keysetName)
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
