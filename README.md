# Trust

Trust provides secure unattended boot of systems (hardware and virtual
machines).  It protects the keys for encrypted filesystem, as well as
a per-machine provisioned certificate/keypair.  It ensures that only an
OS (kernel, initrd (initial filesystem), and kernel command-line) which
has been signed by you will be able to read these keys.

Trust is currently implemented using a combination of UEFI secureboot
and TPM2.  Other hardware assisted architectures are also possible,
and should be easy to implement as alternative implementations of
the Truststore interface.

The following steps implement the trust workflow:

1. 'trust provision' - This step takes a key and certificate which the
   machine can use to uniquely and securely identify itself, e.g. to
   form a cluster with peers.
2. 'trust preinit' - This is run as the first step of an OS install
   sequence.  it will generate a new LUKS passphrase, overwrite the
   existing one on the TPM, and load the new LUKS passphrase in the root
   user keyring for use by the installer.  It will not load any
   pre-existing LUKS passphrase, or load the provisioned key.
3. 'trust setup' - This is run during the signed initrd to copy the
   secrets out of the TPM.  Currently the LUKS passphrase is stored
   in root user keyring, and the provisioned key and certificate are
   stored in a private tmpfs.  Early (signed) userspace can, before
   enabling network, mount all filesystems, and remove the LUKS key from
   keyring.  It can also load the provisioned key into the TPM and
   unmount the tmpfs.

## Notes

1. This is based on the concepts and scripts published at
https://github.com/puzzleos/tpm_eapol_scripts and presented at LSS 2021
by Paul Moore and Joy Latten at
https://www.youtube.com/watch?v=wfJDmfPP1OA).

2. mos ('machine-os') will and mb ('machine-builder') will implement
the proper placement of the trust commands, as well as the secure
bootstrap of userspace.
