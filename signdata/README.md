# signdata

# Update

The signdata layout follows the new format as specified in
~/docs/sb/signdata-format.md.  At present it is all located
under the policy-2 directory.  We could start at policy-1, but
that might confuse some people as the old layout had policy-1
directories under each firmware collection, e.g. snakeoil-qemu.

# This section describes the previous layout

This directory contains subdirectories which each contain:
* pcr7_prod.bin
* pcr7_tpm.bin
* policy-1, containing:
  - pubkey.pem
  - tpmpass-pubkey.pem
  - tpm_luks.policy.signed
  - tpm_passwd.policy.signed

The pcr7 values correspond to a particular firmware.  The policy
signature files are dependent on specific pcr7 values.

The pubkey.pem doesn't necessarily belongs there, but we can fix
that structure later.  Unlike the pcr7 values and signatures, which
require a unique set per firmware, there will really only be two
pubkeys:  one for snakeoil signatures, and one for release
signatures.

The following directories currently exist:

* snakeoil-qemu: This is for use with the snakeoil shim on qemu.
