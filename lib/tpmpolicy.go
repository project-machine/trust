package lib

import (
	"fmt"
	"github.com/urfave/cli"
	"os"

	tpm2 "github.com/canonical/go-tpm2"
	tutil "github.com/canonical/go-tpm2/util"
)

func genLuksPolicy(ctx *cli.Context) error {
	pv := ctx.Int("policy-version")
	if pv < 1 || pv > int(PolicyVersion) {
		return fmt.Errorf("Bad policy version")
	}

	pol := tutil.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)

	luksPcr7, err := os.ReadFile(ctx.String("luks-pcr7-file"))
	if err != nil {
		return err
	}
	pol.PolicyPCR(luksPcr7, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})

	nvV := tpm2.Operand(EAPolicyVersion(TPM2IndexOSKey).String())
	eaVIndex := &tpm2.NVPublic{
		Index:   tpm2.Handle(TPM2IndexEAVersion),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead|tpm2.AttrNVOwnerWrite|tpm2.AttrNVOwnerRead),
		Size:    4,
	}
	eaVName, err := eaVIndex.Name()
	if err != nil {
		return err
	}
	pol.PolicyNV(eaVName, nvV, uint16(0), tpm2.OpEq)

	digest := pol.GetDigest()

	return os.WriteFile(ctx.String("luks-policy-file"), digest, 0600)
}

func genPasswdPolicy(ctx *cli.Context) error {
	pol := tutil.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)

	passwdPcr7, err := os.ReadFile(ctx.String("passwd-pcr7-file"))
	if err != nil {
		return err
	}
	pol.PolicyPCR(passwdPcr7, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})

	digest := pol.GetDigest()

	return os.WriteFile(ctx.String("passwd-policy-file"), digest, 0600)
}

func TpmGenPolicy(ctx *cli.Context) error {
	if err := genLuksPolicy(ctx); err != nil {
		return err
	}
	if err := genPasswdPolicy(ctx); err != nil {
		return err
	}
	return nil
}
