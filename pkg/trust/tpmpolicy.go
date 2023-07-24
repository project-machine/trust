package trust

import (
	"os"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/util"
)

type PolicyData struct {
	Pcr7Prod       string
	Pcr7Tpm        string
	LuksOutFile    string
	PasswdOutFile  string
	PolicyVersion  string
}

// genLuksPolicy creates a policy for reading the LUKS password
// while booted under a production key.
func genLuksPolicy(pData PolicyData) error {
	// Read the uki-production pcr7 value.
	luksPcr7, err := os.ReadFile(pData.Pcr7Prod)
	if err != nil {
		return err
	}
	// Put the pcr7 value in a tpm2.PCRSValues structure so we can compute its digest.
	values := make(tpm2.PCRValues)
	err = values.SetValue(tpm2.HashAlgorithmSHA256, 7, luksPcr7)
	if err != nil {
		return err
	}
	pcrDigest, err := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}, values)
	if err != nil {
		return err
	}

	// Create a tpm2.NVPublic structure that resembles what we would have
	// done via an nvwrite of the policy version to the index.
	// Include TPMA_NV_WRITTEN attribute indicating the index has been written to.
	nvpub := tpm2.NVPublic{Index: tpm2.Handle(TPM2IndexEAVersion), NameAlg: tpm2.HashAlgorithmSHA256, Attrs: tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerWrite|tpm2.AttrNVOwnerRead|tpm2.AttrNVAuthRead|tpm2.AttrNVWritten), Size: 4}

	trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyPCR(pcrDigest, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
	trial.PolicyNV(nvpub.Name(), []byte(pData.PolicyVersion), 0, tpm2.OpEq)
	policyDigest := trial.GetDigest()
	return os.WriteFile(pData.LuksOutFile, policyDigest, 0400)
}

func genPasswdPolicy(pData PolicyData) error {
	// Read the uki-tpm pcr7 value.
	Pcr7Pwd, err := os.ReadFile(pData.Pcr7Tpm)
	if err != nil {
		return err
	}
	// Put the pcr7 value in a tpm2.PCRSValues structure so we can compute its digest.
	values := make(tpm2.PCRValues)
	err = values.SetValue(tpm2.HashAlgorithmSHA256, 7, Pcr7Pwd)
	if err != nil {
		return err
	}
	pcrDigest, err := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}, values)
	if err != nil {
		return err
	}

	// Use a "trial" session to compute the policy digest.
	trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyPCR(pcrDigest, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
	policyDigest := trial.GetDigest()
	return os.WriteFile(pData.PasswdOutFile, policyDigest, 0400)
}

func TpmGenPolicy(pData PolicyData) error {
	// Check inputs
	if pData.Pcr7Prod == "" || pData.Pcr7Tpm == "" {
		return errors.New("Missing pcr7 value(s).")
	}

	if pData.LuksOutFile == "" {
		pData.LuksOutFile = "luks_policy.out"
	}

	if pData.PasswdOutFile == "" {
		pData.PasswdOutFile = "passwd_policy.out"
	}

	// Policy Version if given must be 4 digits. Otherwise use a default of "0001".
	if pData.PolicyVersion == "" {
		pData.PolicyVersion =  PolicyVersion.String()
	} else {
		if len(pData.PolicyVersion) != 4 {
			return errors.New("Policy version should be a four digit string. i.e. 0001")
		}
		for _, c := range pData.PolicyVersion {
			if c < '0' || c > '9' {
				return errors.New("Policy version should be a four digit string. i.e. 0001")
			}
		}
	}

	if err := genLuksPolicy(pData); err != nil {
		return err
	}
	if err := genPasswdPolicy(pData); err != nil {
		return err
	}
	return nil
}
