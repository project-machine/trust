# Building live cd

 * Create bootkit artifacts under .local/share/machine/trust/keys/$keyset - should
   be done by 'trust keyset add'

   ```
   git clone https://github.com/hallyn/bootkit
   cd bootkit
   make build
   umoci unpack --image ../build-bootkit/oci:bootkit \
      ~/.local/share/machine/trust/keys/snakeoil/
   ```
   NOTE - we want to move that from the project into the keyset.

 * cd live
 * build the rootfs
 
    ```
    stacker build --layer-type=squashfs
    ```

   * Note: I  seem to be hitting a bug with this, where it fails to build the second time.

 * Build a signed manifest pointing at your rfs

    ```
    ./build-livecd-rfs
    ```
    or if you're doing things more custom,
    ```
    trust keyset add mostest
    trust project add mostest livecd
    ./build-livecd-rfs --project=mostest:livecd \
          --layer oci:oci:livecd-rootfs-squashfs
    ````
    The result will be a ./livecd.iso.  There will also be a complete
    zot layout under ./zot-cache, if you want to snoop around.

 * boot the usb media. 
 
   ```
   machine init livecd << EOF
    name: livecd
    type: kvm
    ephemeral: false
    description: A fresh VM booting trust LiveCD in SecureBoot mode with TPM
    config:
      name: trust
      uefi: true
      uefi-vars: /home/serge/src/project-machine/trust/live/ovmf-vars.fd
      cdrom: /home/serge/src/project-machine/trust/live/livecd.iso
      boot: cdrom
      tpm: true
      gui: true
      serial: true
      tpm-version: 2.0
      secure-boot: true
      disks:
          - file: /home/serge/src/project-machine/trust/live/livecd.qcow2
            type: ssd
            size: 20G
   EOF
   machine start livecd
   machine gui livecd
    ```
