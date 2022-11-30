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

	"github.com/apex/log"
	"github.com/urfave/cli"
	"github.com/project-machine/trust/lib"
	"github.com/google/uuid"
	"github.com/go-git/go-git/v5"
)

// commands:
//   provision - dangerous
//   boot - read data from tpm, extend pcr7
//   intrd-setup - create new luks key, extend pcr7


var tpmPolicyGenCmd = cli.Command{
	Name: "tpm-policy-gen",
	Usage: "Generate tpm policy",
	Action: doTpmPolicygen,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "pf,passwd-policy-file",
			Usage: "File to which to write password policy",
			Value: "passwd_policy.out",
		},
		cli.StringFlag{
			Name: "lf,luks-policy-file",
			Usage: "File to which to write luks policy",
			Value: "luks_policy.out",
		},
		cli.StringFlag{
			Name: "pp,passwd-pcr7-file",
			Usage: "File from which to read password pcr7",
			Value: "passwd_pcr7.bin",
		},
		cli.StringFlag{
			Name: "lp,luks-pcr7-file",
			Usage: "File from which to read luks pcr7",
			Value: "luks_pcr7.bin",
		},
		cli.IntFlag{
			Name: "pv,policy-version",
			Usage: "Policy version",
			Value: 1,
		},
		cli.StringFlag{
			Name: "pk,passwd-pubkey-file",
			Usage: "File from which to read password policy pubkey",
			Value: "passwd_pubkey.pem",
		},
		cli.StringFlag{
			Name: "lk,luks-pubkey-file",
			Usage: "File from which read write luks policy pubkey",
			Value: "luks_pubkey.pem",
		},
	},
}

func doTpmPolicygen(ctx *cli.Context) error {
	return lib.TpmGenPolicy(ctx)
}

var extendPCR7Cmd = cli.Command{
	Name: "extend-pcr7",
	Usage: "Extend TPM PCR7",
	Action: doTpmExtend,
}

func doTpmExtend(ctx *cli.Context) error {
	t, err := lib.NewTpm2()
	if err != nil {
		return err
	}
	defer t.Close()

	return t.ExtendPCR7()
}

var provisionCmd = cli.Command{
	Name: "provision",
	Usage: "Provision a new system",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "disk",
			Usage: "Disk to provision.  \"any\" to choose one.  Disk must be empty or be wiped.",
		},
		cli.BoolFlag{
			Name: "wipe",
			Usage: "Wipe the chosen disk.",
		},
	},
	Action: doProvision,
}

func doProvision(ctx *cli.Context) error {
	if ctx.NArg() != 2 {
		return fmt.Errorf("Required arguments: certificate and key paths")
	}
	if ctx.String("disk") == "" {
		log.Warnf("No disk specified. No disk will be provisioned")
	}

	if !PathExists("/dev/tpm0") {
		return fmt.Errorf("No TPM.  No other subsystems have been implemented")
	}


	t, err := lib.NewTpm2()
	if err != nil {
		return err
	}
	defer t.Close()
	return t.Provision(ctx)
}

var preInstallCmd = cli.Command{
	Name: "preinstall",
	Usage: "Create and commit new OS key before install",
	Action: doPreInstall,
}

func doPreInstall(ctx *cli.Context) error {
	if !PathExists("/dev/tpm0") {
		return fmt.Errorf("No TPM.  No other subsystems have been implemented")
	}

	t, err := lib.NewTpm2()
	if err != nil {
		return err
	}
	defer t.Close()

	return t.PreInstall()
}

var initrdSetupCmd = cli.Command{
	Name: "initrd-setup",
	Usage: "Setup a provisioned system for boot",
	Action: doInitrdSetup,
}

func doInitrdSetup(ctx *cli.Context) error {
	if !PathExists("/dev/tpm0") {
		return fmt.Errorf("No TPM.  No other subsystems have been implemented")
	}


	t, err := lib.NewTpm2()
	if err != nil {
		return err
	}
	defer t.Close()
	return t.InitrdSetup()
}

func generateManifestCreds(newUUID string) error {
	// Generate a keypair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	err = privKey.Validate()
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory (
		&pem.Block {
			Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)

	// Get the keys repo
	dir, err := os.MkdirTemp("", "keys")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)  // clean up later
	_, err = git.PlainClone(dir, false, &git.CloneOptions{URL: "https://github.com/project-machine/keys.git",})
	if err != nil {
		return err
	}

	// Get the rootCA cert & privKey
	certFile, err := os.ReadFile(filepath.Join(dir, "manifestCA/cert.pem"))
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

	keyFile, err := os.ReadFile(filepath.Join(dir, "manifestCA/privkey.pem"))
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

	// Collect info for certificate template
	CN := fmt.Sprintf("manifest PRODUCT:%s", newUUID)
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

	certTemplate := x509.Certificate {
		SerialNumber:	serialNo,
		Subject:		pkix.Name {
							CommonName: CN,
						},
		NotBefore:		time.Now(),
		NotAfter:		time.Now().AddDate(20,0,0),
		SubjectKeyId:	subjectKeyId[:],
		KeyUsage:		x509.KeyUsageDigitalSignature,
		ExtKeyUsage:	[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	signedCert, err := x509.CreateCertificate(rand.Reader, &certTemplate, CAcert, &pubKey, CAkey)
	if err != nil {
		return err
	}

	// Save the new key and signed certificate
	trustDir, err := getTrustPath()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			os.Remove(filepath.Join(trustDir,"manifest.key"))
			os.Remove(filepath.Join(trustDir,"manifest.crt"))
			os.Remove(filepath.Join(trustDir,"uuid"))
		}
	}()

	// Save private key to trust dir
	err = os.WriteFile(filepath.Join(trustDir, "manifest.key"), keyPEM, 0600)
	if err != nil {
		return err
	}

	// Save signed certificate to trust dir
	certPEM, err := os.Create(filepath.Join(trustDir, "manifest.crt"))
	if err != nil {
		return err
	}
	pem.Encode(certPEM, &pem.Block {Type: "CERTIFICATE", Bytes: signedCert})
	err = certPEM.Close()
	if err != nil {
		return err
	}

	// Save uuid to trust dir
	err = os.WriteFile(filepath.Join(trustDir, "uuid"), []byte(newUUID), 0640)
	if err != nil {
		return err
	}

	fmt.Printf("uuid, manifest.key, and manifest.cert saved in %s directory\n", trustDir)
	return nil
}

var newUUIDCmd = cli.Command{
	Name: "new-uuid",
	Usage: "Generate a uuid and keypair",
	Action: doNewUUID,
}

func doNewUUID(ctx *cli.Context) error {
	// Check if manifest credentials exist
	trustDir, err := getTrustPath()
	if err != nil {
		return err
	}
	_, err = os.Stat(filepath.Join(trustDir, "uuid"))
	if err == nil {
		fmt.Println("Manifest credentials (uuid) already exist.")
		return err
	}
	// Create new manifest credentials
	newUUID := uuid.NewString()
	return  generateManifestCreds(newUUID)
}

const Version = "0.01"

func main() {
	app := cli.NewApp()
	app.Name = "trust"
	app.Usage = "Manage the trustroot"
	app.Version = Version
	app.Commands = []cli.Command{
		initrdSetupCmd,
		preInstallCmd,
		provisionCmd,
		tpmPolicyGenCmd,
		extendPCR7Cmd,
		newUUIDCmd,
	}
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "display additional debug information",
		},
	}

	app.Before = func(c *cli.Context) error {
		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%v\n", err)
	}
}
