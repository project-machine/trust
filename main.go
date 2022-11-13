package main

import (
	"fmt"
	"os"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"

	"github.com/apex/log"
	"github.com/urfave/cli"
	"github.com/project-machine/trust/lib"
	"github.com/google/uuid"
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

func generateKeyPair(newUUID string) error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	err = privKey.Validate()
	if err != nil {
		return err
	}

	CN := fmt.Sprintf("manifest PRODUCT:%s", newUUID)
	template := x509.CertificateRequest {
		Subject: pkix.Name {
			CommonName: CN,
		},
	}

	// Create a CSR with the new key
	newCSR, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory (
		&pem.Block {
			Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)

	csrPEM := pem.EncodeToMemory (
		&pem.Block {
			Type: "CERTIFICATE REQUEST",
			Bytes: newCSR,
		},
	)

	//  get trust dir
	trustDir, err := getTrustPath()
        if err != nil {
		return err
        }

        defer func() {
                if err != nil {
                        os.Remove(filepath.Join(trustDir,"manifest.key"))
                        os.Remove(filepath.Join(trustDir,"manifest.csr"))
                        os.Remove(filepath.Join(trustDir,"uuid"))
                }
        }()

	// Save private key to trust dir
	err = os.WriteFile(filepath.Join(trustDir, "manifest.key"), keyPEM, 0600)
	if err != nil {
		return err
	}

	// Save CSR to trust dir

	err = os.WriteFile(filepath.Join(trustDir, "manifest.csr"), csrPEM, 0640)
	if err != nil {
		return err
	}

	// Save uuid to trust dir
	err = os.WriteFile(filepath.Join(trustDir, "uuid"), []byte(newUUID), 0640)
	if err != nil {
		return err
	}

	fmt.Printf("New uuid, RSA keypair, and CSR saved in %s directory\n", trustDir)
	return nil
}

var newUUIDCmd = cli.Command{
	Name: "new-uuid",
	Usage: "Generate a uuid and keypair",
	Action: doNewUUID,
}

func doNewUUID(ctx *cli.Context) error {
	newUUID := uuid.NewString()
	return  generateKeyPair(newUUID)
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
