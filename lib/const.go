package lib

import "fmt"

type EAPolicyVersion int

func (v EAPolicyVersion) String() string {
	return fmt.Sprintf("%04d", v)
}

type NVIndex int

func (i NVIndex) String() string {
	return fmt.Sprintf("0x%08x", int(i))
}

const AtxInitialPassphrase = "atx-000000000000000000000000000000000000"
const PolicyVersion EAPolicyVersion = 1
const TpmLayoutVersion int = 3
const (
	// This is the password for TPM administration.
	TPM2IndexPassword NVIndex = 0x1500001
	// Version of 'TPM layout'.  Any time a nvindex is added,
	// removed, or changed, bump this version.
	TPM2IndexTPMVersion NVIndex = 0x1500002
	// This is the EA policy version.  Policies to read
	// LUKS nvindex are depending on the version.
	TPM2IndexEAVersion NVIndex = 0x1500020
	// These are the provisioned certificate and key.
	TPM2IndexCert NVIndex = 0x1500021
	TPM2IndexKey  NVIndex = 0x1500022
	// The LUKS password for the sbs
	TPM2IndexSecret NVIndex = 0x1500030
	// The LUKS password for OS filesystems
	TPM2IndexAtxSecret NVIndex = 0x1500040
)

const TPM_PCRS_DEF = "sha256:7"
