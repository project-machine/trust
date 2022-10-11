package main

import (
	"fmt"
	"os"

	"github.com/apex/log"
	"github.com/urfave/cli"
	"github.com/project-machine/trust/lib"
)

// commands:
//   provision - dangerous
//   tpmread - for internal testing, not useful in install
//      "cert", "key", "atx", "sbskey"
//   initrd - read data from tpm, extend pcr7
//   intrd-setup - create new luks key, extend pcr7
var tpmReadCmd = cli.Command{
	Name: "tpm-read",
	Usage: "Debug tpm state",
	Action: doTpmRead,
}

func doTpmRead(ctx *cli.Context) error {
	t := lib.NewTpm2()
	v, err := t.TpmLayoutVersion()
	if err != nil {
		return err
	}
	fmt.Printf("TPM layout version: %s.\n", v)

	v, err = t.TpmEAVersion()
	if err != nil {
		return err
	}
	fmt.Printf("EA Policy version: %s.\n", v)

	return nil
}

const Version = "0.01"

func main() {
	app := cli.NewApp()
	app.Name = "trust"
	app.Usage = "Manage the trustroot"
	app.Version = Version
	app.Commands = []cli.Command{
		tpmReadCmd,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%v\n", err)
	}
}
