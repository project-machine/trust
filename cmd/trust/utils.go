package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// PathExists checks for existense of specified path
func PathExists(d string) bool {
	_, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

func getTrustPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(configDir, "machine", "trust")
	return path, os.MkdirAll(path, 0755)
}

func getSudiDir() (string, error) {
	dataDir, err := UserDataDir()
	if err != nil {
		return "", err
	}
	sudiPath := filepath.Join(dataDir, "machine", "trust")
	return sudiPath, os.MkdirAll(sudiPath, 0755)
}

// UserDataDir returns the user's data directory
func UserDataDir() (string, error) {
	p, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(p, ".local", "share"), nil
}

// ConfPath returns the user's config directory
func ConfPath(cluster string) string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(configDir, "machine", cluster, "machine.yaml")
}

// Get the location where keysets are stored
func getMosKeyPath() (string, error) {
	dataDir, err := UserDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "machine", "trust", "keys"), nil
}

func KeysetExists(keysetname string) bool {
    mosKeyPath, err := getMosKeyPath()
    if err != nil {
        return false
    }
    keysetPath := filepath.Join(mosKeyPath, keysetname)
    if PathExists(keysetPath) {
        return true
    } else {
        return false
    }
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

func createPCR7Index(pcr7file string) (string, error) {
	c, err := os.ReadFile(pcr7file)
	if err != nil {
		return "", err
	}
	for start := 0; start+1 < len(c); start += 2 {
		tmp := c[start]
		c[start] = c[start+1]
		c[start+1] = tmp
	}
	encodedStr := hex.EncodeToString(c)
	return encodedStr, nil
}

func extractPubkey(certPath string) (*rsa.PublicKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("Failed to decode the certificate (%q)", certPath)
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return parsedCert.PublicKey.(*rsa.PublicKey), nil
}

func savePubkeytoFile(pubkey *rsa.PublicKey, outPath string) error {
    pubkeyPem, err := os.Create(outPath)
    if err != nil {
        return err
    }
    pkix, err := x509.MarshalPKIXPublicKey(pubkey)
    if err != nil {
        return err
    }
    err = pem.Encode(pubkeyPem, &pem.Block{Type: "PUBLIC KEY", Bytes: pkix})
    if err != nil {
        return err
    }
    err = os.Chmod(outPath, 0644)
    if err != nil {
        return err
    }
    return nil
}
