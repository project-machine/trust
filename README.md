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

Trust also offers the following subcommands for administration:

   'trust new-uuid --keysetname <name>' - generates a unique product-uuid,
   rsa 2048-bit keypair, and an x509 certificate signed by the manifestCA
   found in the keys repo name with --keysetname. The uuid is placed in
   Subject's CN attribute of the certificate.
   i.e. Subject: CN = manifest PRODUCT:62d38d9f-0d1d-441b-be21-5a7f4173fde1
   The new uuid, keypair, and certificate are placed in the user's local
   config directory, i.e. ~/.config/machine/trust/manifest/.

   'trust initkeyset --keysetname <name> [ --org <organization> ]'  - generates
   a new keys repository containing new keypairs, certs, and uuids. The new
   key repository is located in the user's data directory,
   ~/.local/share/machine/trust/keys/<name>.
   The --org specifies the Organization attribute in the X509 Subject of the
   generated certificates. The key repo may be used whereever a
   keysetname is required.

	'trust keyset pcr7data keysetName --passwdPolicy <pathname> \
									  --luksPolicy <pathname> \
									  --pcr7-tpm <pathname> \
									  --pcr7-prod <pathname> \
									  --pcr7-limited <pathname>
	Adds the specified data to the named keyset. This generates
	the "pcr7data" directory in the keyset.

Exported functions in trust:

   doSudiCert(VMname, keysetname string) - Generates a unique uuid,
   rsa 2048-bit sudi keypair, and x509 certificate that is signed by the
   SudiCA found in the keys repo named with keysetname. This function is
   only called during provisioning. A unique uuid is also generated and added
   to the Subject's CN field of the certificate as well as the Product UUID.
   i.e.
   "Subject: CN = 4cc76b82-948c-44b8-948c-1cc9a7d460d0, serialNumber =
   PID:bc564363-2a8e-44fe-bb0e-54c7f9988ecf SN:4cc76b82-948c-44b8-948c-1cc9a7d460d0"

## Notes

1. This is based on the concepts and scripts published at
https://github.com/puzzleos/tpm_eapol_scripts and presented at LSS 2021
by Paul Moore and Joy Latten at
https://www.youtube.com/watch?v=wfJDmfPP1OA).

2. mos ('machine-os') will and mb ('machine-builder') will implement
the proper placement of the trust commands, as well as the secure
bootstrap of userspace.
