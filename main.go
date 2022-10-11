package main

import (
	"fmt"
	"os"

	"github.com/apex/log"
	tpm2 "github.com/canonical/go-tpm2"
	tlinux "github.com/canonical/go-tpm2/linux"
)

// commands:
//   provision - dangerous
//   tpmread - for internal testing, not useful in install
//      "cert", "key", "atx", "sbskey"
//   initrd - read data from tpm, extend pcr7
//   intrd-setup - create new luks key, extend pcr7

func main() {
	tcti, err := tlinux.OpenDevice("/dev/tpm0")
	if err != nil {
		log.Errorf("Error opening tpm device: %v", err)
		os.Exit(1)
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()
	index, err := tpm.CreateResourceContextFromTPM(0x1c0000a)
	if err != nil {
		log.Errorf("Error creating resource")
		os.Exit(1)
	}
	u, name, err := tpm.NVReadPublic(index)
	fmt.Printf("%v %#v %#v", err, u, name)
}
