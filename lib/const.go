package trust

const AtxInitialPassphrase = "atx-000000000000000000000000000000000000"
const PolicyVersion V3Version = 1
const TpmLayoutVersion int = 3
const (
	// This is the password for TPM administration.
	V3IndexPassword NVIndex = 0x1500001
	// Version of 'TPM layout'.  Any time a nvindex is added,
	// removed, or changed, bump this version.
	V3IndexTPMVersion NVIndex = 0x1500002
	// This is the EA policy version.  Policies to read
	// LUKS nvindex are depending on the version.
	V3IndexEAVersion NVIndex = 0x1500020
	// These are the provisioned certificate and key.
	V3IndexCert NVIndex = 0x1500021
	V3IndexKey  NVIndex = 0x1500022
	// The LUKS password for the sbs
	V3IndexSecret NVIndex = 0x1500030
	// The LUKS password for OS filesystems
	V3IndexAtxSecret NVIndex = 0x1500040
)

const TPM_PCRS_DEF = "sha256:7"
