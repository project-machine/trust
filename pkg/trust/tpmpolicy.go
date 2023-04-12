package trust

import (
	"fmt"
	"github.com/urfave/cli"
	"os"

	tpm2 "github.com/canonical/go-tpm2"
	tutil "github.com/canonical/go-tpm2/util"
)

func getHex(v []byte) (byte, bool) {
	isok := func(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') }

	if !isok(v[0]) || !isok(v[1]) {
		return byte(0), false
	}
	if len(v) < 2 {
		return byte(0), false
	}
	if len(v) >= 3 && v[2] != ' ' {
		return byte(0), false
	}

	var b byte
	n, err := fmt.Sscanf(string(v), "%x", &b)
	return b, n == 1 && err == nil
}

func parsePcr7(v []byte) ([]byte, error) {
	if len(v) == 32 {
		return v, nil
	}

	orig := v
	// Try to be accomodating of mess input, like
	// FS0:\>   CE CF 08 59 D0 C8 2F 9B 07 4D 48 D3 00 CC 83 DA E0 5D F9 8D A4 14 4F 4B EA EF 88 FA F9 67 F3 8C
	// [PCR07]  25 4D 1D 38 54 F7 1A D2 2F 70 46 D0 37 A8 98 A5 18 80 41 5B 01 EC DC 57 7E 24 2A 14 61 16 EE A0
	// All we want is 25 4D 1D 38 54 F7 1A D2 2F 70 46 D0 37 A8 98 A5 18 80 41 5B 01 EC DC 57 7E 24 2A 14 61 16 EE A0
	// So look for 32 valid pairs of hex digits separated by one space.
	output := []byte{}
	for {
		if len(output) == 32 {
			for i := 0; i < 31; i += 2 {
				output[i], output[i+1] = output[i+1], output[i]
			}
			return output, nil
		}
		if len(v) < 1 {
			return []byte{}, fmt.Errorf("Short input (%s)", orig)
		}
		n, ok := getHex(v)
		if !ok {
			v = v[1:]
			continue
		}
		output = append(output, n)
		if len(output) == 32 {
			for i := 0; i < 31; i += 2 {
				output[i], output[i+1] = output[i+1], output[i]
			}
			return output, nil
		}
		s := 3
		if len(v) < 3 {
			s = len(v)
		}
		v = v[s:]
	}
	return []byte{}, fmt.Errorf("Invalid input")
}

func readPcr7(p string) ([]byte, error) {
	v, err := os.ReadFile(p)
	if err != nil {
		return []byte{}, err
	}

	return parsePcr7(v)
}

func genLuksPolicy(ctx *cli.Context) error {
	pv := ctx.Int("policy-version")
	if pv < 1 || pv > int(PolicyVersion) {
		return fmt.Errorf("Bad policy version")
	}

	pol := tutil.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)

	luksPcr7, err := readPcr7(ctx.String("luks-pcr7-file"))
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

	passwdPcr7, err := readPcr7(ctx.String("passwd-pcr7-file"))
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
