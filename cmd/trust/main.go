package main

import (
	"os"

	"github.com/apex/log"
	"github.com/urfave/cli"
)

//   provision - dangerous
//   boot - read data from tpm, extend pcr7
//   intrd-setup - create new luks key, extend pcr7


// Version of trust
const Version = "0.01"

func main() {
	app := cli.NewApp()
	app.Name = "trust"
	app.Usage = "Manage the trustroot"
	app.Version = Version
	app.Commands = []cli.Command{
		initrdSetupCmd,
		preInstallCmd,
		provisionCmd,
		tpmPolicyGenCmd,
		extendPCR7Cmd,

		// keyset
		keysetCmd,

		// project
		projectCmd,

		// sudo
		genSudiCmd,
	}
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "display additional debug information",
		},
	}

	app.Before = func(c *cli.Context) error {
		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%v\n", err)
	}
}
