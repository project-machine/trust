# Building live cd

 * cd live
 * build the rootfs
 
    ```
    stacker build --layer-type=squashfs
    ```

   * Note: I  seem to be hitting a bug with this, where it fails to build the second time.

 * get privkey.pem and cert.pem and run 'build-media'

   ```
   keydir="/path/to/keys"
   ./build-media \
        --cert=$keydir/manifest/cert.pem  \
        --key=$keydir/manifest/privkey.pem \
        out.img \
        docker://zothub.io/machine/bootkit/bootkit:0.0.5.230327-squashfs \
        oci:./oci:rootfs-squashfs
    ```

 * boot the usb media. 
 
   * atomix-vm-builder wants qcow2 format, so convert to qcow2
   * build-media left 'ovmf-vars.fd' and 'ovmf-code.fd' in same dir as out.img

    ```
    rm -f out.qcow2 
    qemu-img create -fqcow2 -b out.img -Fraw out.qcow2 
    atomix-vm-builder run \
       --usb-hdd-path=out.qcow2 \
       --tpm --tpm-version=2.0 \
       --secure-boot --uefi \
       --uefi-vars=ovmf-vars.fd \
       --uefi-code=ovmf-code.fd \
       --num-hdd=0 --num-ssd=0 \
       --kvmopts="-echr 0x05 -device VGA -vnc :9000"
