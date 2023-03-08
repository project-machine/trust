package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/go-git/go-git/v5"
	"github.com/project-machine/trust/pkg/trust"
	"github.com/urfave/cli"
)

// commands:
//   provision - dangerous
//   boot - read data from tpm, extend pcr7
//   intrd-setup - create new luks key, extend pcr7

var tpmPolicyGenCmd = cli.Command{
	Name:   "tpm-policy-gen",
	Usage:  "Generate tpm policy",
	Action: doTpmPolicygen,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "pf,passwd-policy-file",
			Usage: "File to which to write password policy",
			Value: "passwd_policy.out",
		},
		cli.StringFlag{
			Name:  "lf,luks-policy-file",
			Usage: "File to which to write luks policy",
			Value: "luks_policy.out",
		},
		cli.StringFlag{
			Name:  "pp,passwd-pcr7-file",
			Usage: "File from which to read password pcr7",
			Value: "passwd_pcr7.bin",
		},
		cli.StringFlag{
			Name:  "lp,luks-pcr7-file",
			Usage: "File from which to read luks pcr7",
			Value: "luks_pcr7.bin",
		},
		cli.IntFlag{
			Name:  "pv,policy-version",
			Usage: "Policy version",
			Value: 1,
		},
		cli.StringFlag{
			Name:  "pk,passwd-pubkey-file",
			Usage: "File from which to read password policy pubkey",
			Value: "passwd_pubkey.pem",
		},
		cli.StringFlag{
			Name:  "lk,luks-pubkey-file",
			Usage: "File from which read write luks policy pubkey",
			Value: "luks_pubkey.pem",
		},
	},
}

func doTpmPolicygen(ctx *cli.Context) error {
	return trust.TpmGenPolicy(ctx)
}

var extendPCR7Cmd = cli.Command{
	Name:   "extend-pcr7",
	Usage:  "Extend TPM PCR7",
	Action: doTpmExtend,
}

func doTpmExtend(ctx *cli.Context) error {
	t, err := trust.NewTpm2()
	if err != nil {
		return err
	}
	defer t.Close()

	return t.ExtendPCR7()
}

var provisionCmd = cli.Command{
	Name:  "provision",
	Usage: "Provision a new system",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "disk",
			Usage: "Disk to provision.  \"any\" to choose one.  Disk must be empty or be wiped.",
		},
		cli.BoolFlag{
			Name:  "wipe",
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

	t, err := trust.NewTpm2()
	if err != nil {
		return err
	}
	defer t.Close()
	return t.Provision(ctx)
}

var preInstallCmd = cli.Command{
	Name:   "preinstall",
	Usage:  "Create and commit new OS key before install",
	Action: doPreInstall,
}

func doPreInstall(ctx *cli.Context) error {
	if !PathExists("/dev/tpm0") {
		return fmt.Errorf("No TPM.  No other subsystems have been implemented")
	}

	t, err := trust.NewTpm2()
	if err != nil {
		return err
	}
	defer t.Close()

	return t.PreInstall()
}

var initrdSetupCmd = cli.Command{
	Name:   "initrd-setup",
	Usage:  "Setup a provisioned system for boot",
	Action: doInitrdSetup,
}

func doInitrdSetup(ctx *cli.Context) error {
	if !PathExists("/dev/tpm0") {
		return fmt.Errorf("No TPM.  No other subsystems have been implemented")
	}

	t, err := trust.NewTpm2()
	if err != nil {
		return err
	}
	defer t.Close()
	return t.InitrdSetup()
}

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

// Version of trust
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
		initKeysetCmd,
		genSudiCmd,
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
