package main

// Project == product

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/project-machine/trust/pkg/trust"
	"github.com/urfave/cli"
)

var projectCmd = cli.Command{
	Name:  "project",
	Usage: "Generate a uuid and keypair",
	Subcommands: []cli.Command{
		cli.Command{
			Name:      "list",
			Action:    doListProjects,
			Usage:     "list projects",
			ArgsUsage: "<keyset-name>",
		},
		cli.Command{
			Name:      "add",
			Action:    doAddProject,
			Usage:     "add a new project",
			ArgsUsage: "<keyset-name> <project-name>",
		},
	},
}

func doAddProject(ctx *cli.Context) error {
	args := ctx.Args()
	if len(args) != 2 {
		return errors.New("Projects belong to a keyset. Specify keyset name to list the projects in a keyset.")
	}

	keysetName := args[0]
	projName := args[1]

	trustDir, err := getMosKeyPath()
	if err != nil {
		return err
	}

	keysetPath := filepath.Join(trustDir, keysetName)
	projPath := filepath.Join(keysetPath, "manifest", projName)
	if PathExists(projPath) {
		return fmt.Errorf("Project %s already exists", projName)
	}

	if err = os.Mkdir(projPath, 0750); err != nil {
		return errors.Wrapf(err, "Failed creating project directory %q", projPath)
	}

	// Create new manifest credentials
	err = generateNewUUIDCreds(keysetName, projPath)
	if err != nil {
		os.RemoveAll(projPath)
		return errors.Wrapf(err, "Failed creating new project")
	}

	if err := trust.EnsureDir(filepath.Join(projPath, "sudi")); err != nil {
		os.RemoveAll(projPath)
		return errors.Wrapf(err, "Failed creating sudi directory for new project")
	}

	fmt.Printf("New credentials saved in %s directory\n", projPath)
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

func doListProjects(ctx *cli.Context) error {
	args := ctx.Args()
	if len(args) == 0 {
		return errors.New("Projects belong to a keyset. Specify keyset name to list the projects in a keyset.")
	}

	keysetName := args[0]
	trustDir, err := getMosKeyPath()
	if err != nil {
		return err
	}
	keysetPath := filepath.Join(trustDir, keysetName)
	if !PathExists(keysetPath) {
		return fmt.Errorf("Keyset not found: %s", keysetName)
	}

	keysetPath = filepath.Join(keysetPath, "manifest")
	if !PathExists(keysetPath) {
		fmt.Printf("No projects found")
		return nil
	}

	dirs,  err := os.ReadDir(keysetPath)
	if err != nil {
		return fmt.Errorf("Failed reading keys directory %q: %w", trustDir, err)
	}

	fmt.Printf("Projects in %s:\n", keysetName)
	for _, keyname := range dirs {
		fmt.Printf("%s\n", keyname.Name())
	}

	return nil
}
