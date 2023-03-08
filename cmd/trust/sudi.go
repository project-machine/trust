package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/urfave/cli"
)

var genSudiCmd = cli.Command{
	Name:      "gen-sudi",
	Usage:     "Generate and sign sudi cert",
	UsageText: "CACert, private-key, output-dir, product-uuid [, machine-uuid]",
	Action:    doGenSudi,
}

func doGenSudi(ctx *cli.Context) error {
	args := ctx.Args()
	if len(args) != 3 && len(args) != 4 {
		return fmt.Errorf("Got %d args, want 3 or 4", len(args))
	}
	var myUUID string
	caCertPath := args[0]
	caKeyPath := args[1]
	destdir := args[2]
	prodUUID := args[3]
	if len(args) == 5 {
		myUUID = args[4]
	} else {
		myUUID = uuid.NewString()
		fmt.Fprintf(os.Stderr, "Using machine-uuid '%s'\n", myUUID)
	}

	caCert, err := readCertificateFromFile(caCertPath)
	if err != nil {
		return err
	}
	caKey, err := readPrivKeyFromFile(caKeyPath)
	if err != nil {
		return err
	}

	certTmpl := newCertTemplate(prodUUID, myUUID)

	if err := os.MkdirAll(destdir, 0755); err != nil {
		return fmt.Errorf("Failed to create %s: %v", destdir, err)
	}

	if err := SignCert(&certTmpl, caCert, caKey, destdir); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Wrote cert.pem and privkey.pem in %s\n", destdir)
	return nil
}

// Generate sudi private key and cert.
func doSudiCert(VMname, keyset string) error {
	if VMname == "" {
		return errors.New("VM name must be provided")
	}

	// Check if the VM has been initialized
	cPath := ConfPath(VMname)
	if !PathExists(cPath) {
		return fmt.Errorf("%s has not been initialized", VMname)
	}

	// Check if a sudi key or cert already exists for the VM
	sudiDir, err := getSudiDir()
	if err != nil {
		return err
	}
	sudiPath := filepath.Join(sudiDir, VMname)
	_, err = os.Stat(filepath.Join(sudiPath, "privkey.pem"))
	if err == nil {
		fmt.Printf("A privkey.pem already exists for %s in %s.\n", VMname, sudiPath)
		return err
	}
	_, err = os.Stat(filepath.Join(sudiPath, "cert.pem"))
	if err == nil {
		fmt.Printf("A cert.pem already exists for %s in %s.\n", VMname, sudiPath)
		return err
	}

	// Prepare the cert template
	// Get this machine's UUID to add to the Subject in cert
	trustDir, err := getTrustPath()
	if err != nil {
		return err
	}
	content, err := os.ReadFile(filepath.Join(trustDir, "manifest/uuid"))
	if err != nil {
		return err
	}
	productUUID := string(content)

	certTemplate := newCertTemplate(productUUID, uuid.NewString())

	// get the CA info
	CAcert, CAprivkey, err := getCA("sudi-ca", keyset)
	if err != nil {
		return err
	}

	err = os.MkdirAll(sudiPath, 0755)
	if err != nil {
		return err
	}
	err = SignCert(&certTemplate, CAcert, CAprivkey, sudiPath)
	if err != nil {
		return err
	}
	log.Infof("Generated sudi key and cert saved in %s directory\n", sudiPath)
	return nil
}

func newCertTemplate(productUUID, machineUUID string) x509.Certificate {
	return x509.Certificate{
		Subject: pkix.Name{
			SerialNumber: fmt.Sprintf("PID:%s SN:%s", productUUID, machineUUID),
			CommonName:   machineUUID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Date(2099, time.December, 31, 23, 0, 0, 0, time.UTC),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}
