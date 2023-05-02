package main

import (
	"crypto/x509"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"encoding/json"

	"github.com/apex/log"
	"github.com/go-git/go-git/v5"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	tree "github.com/project-machine/trust/pkg/printdirtree"
	"github.com/project-machine/trust/pkg/trust"
	"github.com/urfave/cli"
)

var KeysetKeyDirs = []string{
	"manifest",
	"manifest-ca",
	"pcr7data",
	"sudi-ca",
	"tpmpol-admin",
	"tpmpol-luks",
	"uefi-db",
	"uefi-kek",
	"uefi-pk",
	"uki-limited",
	"uki-production",
	"uki-tpm",
}

const (
	middleSym = "├──"
	columnSym = "│"
	lastSym   = "└──"
	firstSym  = middleSym
)

func isValidKeyDir(keydir string) bool {
	for _, dir := range KeysetKeyDirs {
		if dir == keydir {
			return true
		}
	}
	return false
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
	err := os.MkdirAll(keysetPath, 0750)
	if err != nil {
		return err
	}

	for _, dir := range KeysetKeyDirs {
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
	err = generaterootCA(filepath.Join(keysetPath, "uefi-pk"), &caTemplate, doGUID)
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
	CAcert, CAprivkey, err := getCA("uefi-pk", keysetName)
	if err != nil {
		return err
	}
	// reuse certTemplate with some modifications
	certTemplate.Subject.CommonName = "UEFI KEK"
	certTemplate.NotAfter = time.Now().AddDate(50, 0, 0)
	certTemplate.ExtKeyUsage = nil
	err = SignCert(&certTemplate, CAcert, CAprivkey, filepath.Join(keysetPath, "uefi-kek"))
	if err != nil {
		return err
	}
	guid := uuid.NewString()
	err = os.WriteFile(filepath.Join(keysetPath, "uefi-kek", "guid"), []byte(guid), 0640)
	if err != nil {
		return err
	}

	// Generate sample uuid, manifest key and cert
	mName := filepath.Join(keysetPath, "manifest", "default")
	if err = trust.EnsureDir(mName); err != nil {
		return errors.Wrapf(err, "Failed creating default project directory")
	}
	sName := filepath.Join(mName, "sudi")
	if err = trust.EnsureDir(sName); err != nil {
		return errors.Wrapf(err, "Failed creating default sudi directory")
	}

	if err = generateNewUUIDCreds(keysetName, mName); err != nil {
		return errors.Wrapf(err, "Failed creating default project keyset")
	}

	return nil
}

var keysetCmd = cli.Command{
	Name:  "keyset",
	Usage: "Administer keysets for mos",
	Subcommands: []cli.Command{
		cli.Command{
			Name:   "list",
			Action: doListKeysets,
			Usage:  "list keysets",
		},
		cli.Command{
			Name:      "add",
			Action:    doAddKeyset,
			Usage:     "add a new keyset",
			ArgsUsage: "<keyset-name>",
			Flags: []cli.Flag{
				cli.StringSliceFlag{
					Name:  "org, Org, organization",
					Usage: "X509-Organization field to add to certificates when generating a new keyset. (optional)",
				},
			},
		},
		cli.Command{
			Name:      "show",
			Action:    doShowKeyset,
			Usage:     "show keyset key values or paths",
			ArgsUsage: "<keyset-name> <key> [<item>]",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "path",
					Usage: "Show path only to keyset key item",
				},
				cli.BoolFlag{
					Name:  "value",
					Usage: "Show value only of keyset key item",
				},
			},
		},
		cli.Command{
			Name:		"pcr7data",
			Action:		doAddPCR7data,
			Usage:		"include the specified pcr7data into keyset",
			ArgsUsage:	"<keyset-name>",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "pcr7-tpm",
					Usage: "Pathname to the pcr7 tpm binary file",
				},
				cli.StringFlag{
					Name: "pcr7-limited",
					Usage: "Pathname to the pcr7 limited binary file",
				},
				cli.StringFlag{
					Name: "pcr7-prod",
					Usage: "Pathname to the pcr7 production binary file",
				},
				cli.StringFlag{
					Name: "passwdPolicy",
					Usage: "Pathname to the tpm passwd policy file (optional)",
				},
				cli.StringFlag{
					Name: "luksPolicy",
					Usage: "Pathname to the luks policy file (optional)",
				},
			},
		},
	},
}

func doAddKeyset(ctx *cli.Context) error {
	args := ctx.Args()
	if len(args) != 1 {
		return errors.New("A name for the new keyset is required (please see \"--help\")")
	}

	keysetName := args[0]
	if keysetName == "" {
		return errors.New("Please specify keyset name")
	}

	Org := ctx.StringSlice("org")
	if Org == nil {
		log.Infof("X509-Organization field for new certificates not specified.")
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

func doListKeysets(ctx *cli.Context) error {
	if len(ctx.Args()) != 0 {
		return fmt.Errorf("Wrong number of arguments (please see \"--help\")")
	}
	moskeysetPath, err := getMosKeyPath()
	if err != nil {
		return err
	}
	dirs, err := os.ReadDir(moskeysetPath)
	if err != nil {
		return fmt.Errorf("Failed reading keys directory %q: %w", moskeysetPath, err)
	}

	for _, keyname := range dirs {
		fmt.Printf("%s\n", keyname.Name())
	}

	return nil
}

func doShowKeyset(ctx *cli.Context) error {
	if len(ctx.Args()) == 0 {
		return fmt.Errorf("Please specify keyset name. Select from 'trust keyset list'")
	}

	keysetName := ctx.Args()[0]
	if keysetName == "" {
		return fmt.Errorf("Please specify keyset name. Select from 'trust keyset list'")
	}

	moskeysetPath, err := getMosKeyPath()
	if err != nil {
		return err
	}

	keysetPath := filepath.Join(moskeysetPath, keysetName)
	if !PathExists(keysetPath) {
		return fmt.Errorf("Unknown keyset '%s', cannot find keyset at path: %q", keysetName, keysetPath)
	}

	// no keyset key name specified only, print path if --path, otherwise list all key dir names
	if len(ctx.Args()) < 2 {
		if ctx.Bool("path") {
			fmt.Printf("%s\n", keysetPath)
			for _, keyDir := range KeysetKeyDirs {
				keyPath := filepath.Join(keysetPath, keyDir)
				fmt.Printf("%s\n", keyPath)
			}
		} else {

			if err := tree.PrintDirs(keysetPath, KeysetKeyDirs); err != nil {
				return err
			}
		}
		return nil
	}

	keyName := ctx.Args()[1]
	if keyName == "" {
		return fmt.Errorf("Please specify keyset key name, must be one of: %s", strings.Join(KeysetKeyDirs, ", "))
	}

	if !isValidKeyDir(keyName) {
		return fmt.Errorf("Invalid keyset key name '%s':, must be one of: %s", strings.Join(KeysetKeyDirs, ", "))
	}

	keyPath := filepath.Join(keysetPath, keyName)
	if !PathExists(keyPath) {
		return fmt.Errorf("Keyset %s key %q does not exist at %q", keysetName, keyName, keyPath)
	}

	if len(ctx.Args()) > 2 {
		item := ctx.Args()[2]
		fullPath := filepath.Join(keyPath, item)
		if !PathExists(fullPath) {
			return fmt.Errorf("Failed reading keyset %s key %s item %s at %q: %w", keysetName, keyName, item, fullPath, err)
		}

		contents, err := os.ReadFile(fullPath)
		if err != nil {
			return fmt.Errorf("Failed reading keyset %s key %s item %s at %q: %w", keysetName, keyName, item, fullPath, err)
		}
		if ctx.Bool("path") {
			fmt.Println(fullPath)
		} else if ctx.Bool("value") {
			fmt.Printf("%s", string(contents))
		} else {
			fmt.Printf("%s\n%s\n", fullPath, string(contents))
		}
		return nil
	}

	// no item specified, crawl dir and print contents or path
	keyFiles, err := os.ReadDir(keyPath)
	if err != nil {
		return fmt.Errorf("keyset %s key %s directory %q: %w", keysetName, keyName, keyPath, err)
	}

	printPath := ctx.Bool("path")
	for _, dEntry := range keyFiles {
		if dEntry.IsDir() {
			continue
		}
		keyFile := dEntry.Name()
		fullPath := filepath.Join(keyPath, keyFile)
		contents, err := os.ReadFile(fullPath)
		if err != nil {
			return fmt.Errorf("Failed reading keyset %s key %s item %s at %q: %w", keysetName, keyName, keyFile, fullPath, err)
		}
		if printPath {
			fmt.Println(fullPath)
		} else {
			fmt.Printf("%s\n%s\n", fullPath, string(contents))
		}
	}

	return nil
}

type Pcr7Data struct {
	limited      string
	tpm          string
	production   string
	passwdPolicy string
	luksPolicy   string
}

func doAddPCR7data(ctx *cli.Context) error {
	var p Pcr7Data
	args := ctx.Args()
	if len(args) != 1 {
		return errors.New("Missing arguments")
	}

	keysetName := args[0]

	p.passwdPolicy = ctx.String("passwdPolicy")
	p.luksPolicy = ctx.String("luksPolicy")
	p.limited = ctx.String("pcr7-limited")
	p.tpm = ctx.String("pcr7-tpm")
	p.production = ctx.String("pcr7-prod")

	if err := addPcr7data(keysetName, p); err != nil {
		return err
	}
	return nil
}

func addPcr7data(keysetName string, pdata Pcr7Data) error {
	var err error
	var notexist = true
	var moskeypath, pcrIndex, newFile string
	var tpmpolAdminpubkey, tpmpolLukspubkey *rsa.PublicKey
	var jsonInfo []byte
	type PCR7info struct {
		Key string `json:"key"`
		KeyType string `json:"key_type"`
		Date string `json:"est_date"`
		Comment string `json:"comment"`
	}

	pcr7 := make(map[string]string)

	if keysetName == "" {
		return errors.New("Please specify a keyset name")
	}

	pcr7["limited"] = pdata.limited
	pcr7["tpm"] = pdata.tpm
	pcr7["production"] = pdata.production

	if pcr7["limited"] == "" || pcr7["tpm"] == "" || pcr7["production"] == "" {
		return errors.New("Must specify all 3 pcr7 values: tpm, limited and production")
	}

	// Make sure the pcr7 files exist
	for _, path := range pcr7 {
		if !PathExists(path) {
			return fmt.Errorf("%s does not exist.", path)
		}
	}

	// For now, don't generate. Only accept the 2 policies.
	if pdata.passwdPolicy == "" || !PathExists(pdata.passwdPolicy) {
		return errors.New("The passwd policy file is missing.")
	}
	if pdata.luksPolicy == "" || !PathExists(pdata.luksPolicy) {
		return errors.New("The luks policy file is missing.")
	}

	moskeypath, err = getMosKeyPath()
	if err != nil {
		return err
	}
	keysetPath := filepath.Join(moskeypath, keysetName)
	if !PathExists(keysetPath) {
		return fmt.Errorf("The keyset, %s, does not exist.", keysetName)
	}

	// Its ok if pcr7data dir already exists. We might be adding additional signdata
	pcr7dataPath := filepath.Join(keysetPath, "pcr7data/policy2")
	if !PathExists(pcr7dataPath) {
		err = os.MkdirAll(keysetPath, 0750)
		if err != nil  {
			return err
		}
	} else {
		notexist = false
	}

	defer func() {
		if err != nil && notexist == true {
			os.RemoveAll(filepath.Join(keysetPath, "pcr7data"))
		}
	}()

	// Check to see if public keys already exist for this keyset, if not
	// then extract public keys and save them
	pcr7dataPubkeys := filepath.Join(pcr7dataPath, "pubkeys")
	if !PathExists(pcr7dataPubkeys) {
		if err = trust.EnsureDir(pcr7dataPubkeys); err != nil {
			return errors.New("Failed to create directory for public keys")
		}
	}

	tpmpolAdminpubkey, err = extractPubkey(filepath.Join(keysetPath, "tpmpol-admin/cert.pem"))
	if err != nil {
		return err
	}
	err = savePubkeytoFile(tpmpolAdminpubkey, filepath.Join(pcr7dataPubkeys, "tpmpass-snakeoil.pem"))
	if err != nil {
		return err
	}
	tpmpolLukspubkey, err = extractPubkey(filepath.Join(keysetPath, "tpmpol-luks/cert.pem"))
	if err != nil {
		return  err
	}
	err = savePubkeytoFile(tpmpolLukspubkey, filepath.Join(pcr7dataPubkeys, "luks-snakeoil.pem"))
	if err != nil {
		return err
	}

	// - Generate the index for pcr7-limited.bin.
	//    Add the binary pcr7 values into this index.
	// - Generate the index for pcr7-production.bin.
	//    Add the signed tpm-luks policy into this index.
	// - Generate the index for pcr7-tpm.bin.
	//    Add the signed tpm-passwd policy into this index.
	for key, path := range pcr7 {
		// create index used to name the sub-directories under policy-2 directory
		pcrIndex, err = createPCR7Index(path)
		if err != nil {
			return err
		}
		indexdir := filepath.Join(pcr7dataPath, pcrIndex[0:2], pcrIndex[2:])
		if err = trust.EnsureDir(indexdir); err != nil {
			return err
		}

		// create info.json
		jsonFile := filepath.Join(indexdir, "info.json")

		date := time.Now()
		formatted := date.Format("2006-01-02")
		timestamp := strings.ReplaceAll(formatted, "-", "")
		info := &PCR7info{Key: keysetName, KeyType: key, Date: timestamp, Comment: "mos"+" "+keysetName}
		jsonInfo, err = json.Marshal(info)
		if err != nil {
			return err
		}
		if err = os.WriteFile(jsonFile, jsonInfo, 0644); err != nil {
				return err
		}

		// write out info
		switch key {
		case "limited" :
			newFile = filepath.Join(indexdir, "pcr_limited.bin")
			if err = trust.CopyFile(pcr7["limited"], newFile); err != nil {
				return err
			}
			newFile = filepath.Join(indexdir, "pcr_tpm.bin")
			if err = trust.CopyFile(pcr7["tpm"], newFile); err != nil {
				return err
			}
			newFile = filepath.Join(indexdir, "pcr_prod.bin")
			if err = trust.CopyFile(pcr7["production"], newFile); err != nil {
				return err
			}
		case "tpm" :
			// Sign the policy
			newFile = filepath.Join(indexdir, "tpm_passwd.policy.signed")
			signingKey := filepath.Join(keysetPath, "tpmpol-admin/privkey.pem")
			if err = trust.Sign(pdata.passwdPolicy, newFile, signingKey); err != nil {
				return err
			}
		case "production" :
			// Sign the policy
			newFile = filepath.Join(indexdir, "tpm_luks.policy.signed")
			signingKey := filepath.Join(keysetPath, "tpmpol-luks/privkey.pem")
			if err = trust.Sign(pdata.luksPolicy, newFile, signingKey); err != nil {
				return err
			}
		default :
			return errors.New("Unrecognized uki key")
		}
	}
	return nil
}
