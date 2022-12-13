package main

import (
	"fmt"
	"os"
	"errors"
	"time"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/sha1"
	"encoding/pem"
	"path/filepath"
	"math/big"

	"github.com/google/uuid"
)

// Generate sudi private key and cert.
func doSudiCert(VMname string) error {
	if VMname == "" {
        return errors.New("VM name must be provided")
	}

	// Check if the VM has been initialized
	cPath := ConfPath(VMname)
	if ! PathExists(cPath) {
		return fmt.Errorf("%s has not been initialized.", VMname)
	}

	// Check if a sudi key or cert already exists for the VM
	sudiDir, err := getSudiDir()
	if err != nil {
		return err
	}
	sudiPath := filepath.Join(sudiDir, VMname)
	_, err = os.Stat(filepath.Join(sudiPath, "sudi.key"))
	if err == nil {
		fmt.Printf("A sudi.key already exists for %s.\n", VMname)
		return err
	}
	_, err = os.Stat(filepath.Join(sudiPath, "sudi.crt"))
	if err == nil {
		fmt.Printf("A sudi.crt already exists for %s.\n", VMname)
		return err
	}

	// Generate an RSA Keypair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	err = privKey.Validate()
	if err != nil {
		return err
	}

	// Get the keys repo
	dir, err := getKeysrepo()
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)  // clean up later

	// Get the rootCA cert & privKey
	certFile, err := os.ReadFile(filepath.Join(dir, "sudiCA/cert.pem"))
	if err != nil {
		return err
	}
	pemBlock, _ := pem.Decode(certFile)
	if pemBlock == nil {
		return errors.New("pem.Decode cert failed")
	}
	CAcert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}

	keyFile, err := os.ReadFile(filepath.Join(dir, "sudiCA/privkey.pem"))
	if err != nil {
		return err
	}
	pemBlock, _ = pem.Decode(keyFile)
	if pemBlock == nil {
		return errors.New("pem.Decode cert failed")
	}
	CAkey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return err
	}

	// Get this machine's UUID to add to the Subject in cert
	trustDir, err := getTrustPath()
	if err != nil {
		return err
	}
	productUUID, err := os.ReadFile(filepath.Join(trustDir, "uuid"))
	if err != nil {
		return err
	}

	machineUUID := uuid.NewString()

	// Subject's Serial no.
	SubjectSerialno := fmt.Sprintf("PID:%s SN:%s", string(productUUID[:]), string(machineUUID[:]))

	// Certificate Serial no.
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
	subjectKeyId := sha1.Sum(publicKeyBytes)

	// KeyUsage
	certTemplate := x509.Certificate {
		SerialNumber:	serialNo,
		Subject:		pkix.Name {
							SerialNumber: SubjectSerialno,
							CommonName: machineUUID,
						},
		NotBefore:		time.Now(),
		NotAfter:		time.Date(2099, time.December, 31, 23, 0, 0, 0, time.UTC),
		SubjectKeyId:	subjectKeyId[:],
		KeyUsage:		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment,
		ExtKeyUsage:	[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	serverCert, err := x509.CreateCertificate(rand.Reader, &certTemplate, CAcert, &pubKey, CAkey)
	if err != nil {
		return err
	}

	// Save the newly generated sudi cert nd privkey to disk
	err = os.MkdirAll(sudiPath, 0755)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			os.Remove(filepath.Join(sudiPath,"sudi.crt"))
			os.Remove(filepath.Join(sudiPath,"sudi.key"))
		}
	}()

	certPEM, err := os.Create(filepath.Join(sudiPath, "sudi.crt"))
	if err != nil {
		return err
	}
	pem.Encode(certPEM, &pem.Block {Type: "CERTIFICATE", Bytes: serverCert})
	err = certPEM.Close()
	if err != nil {
		return err
	}
	err = os.Chmod(filepath.Join(sudiPath, "sudi.crt"), 0640)
	if err != nil {
		return err
	}

	keyPEM, err := os.Create(filepath.Join(sudiPath, "sudi.key"))
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	pem.Encode(keyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	err = keyPEM.Close()
	if err != nil {
		return err
	}
	err = os.Chmod(filepath.Join(sudiPath, "sudi.key"), 0600)
	if err != nil {
		return err
	}

	fmt.Printf("Generated sudi.crt and sudi.key saved in %s directory\n", sudiPath)
	return nil
}
