package main

import (
	"github.com/project-machine/trust/pkg/trust"
	"github.com/urfave/cli"
)

var tpmPolicyGenCmd = cli.Command{
	Name:   "tpm-policy-gen",
	Usage:  "Generate tpm policy",
	Action: doTpmPolicygen,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "pf,passwd-policy-file",
			Usage: "File to which to write password policy",
			Value: "passwd_policy.out",
		},
		cli.StringFlag{
			Name:  "lf,luks-policy-file",
			Usage: "File to which to write luks policy",
			Value: "luks_policy.out",
		},
		cli.StringFlag{
			Name:  "pp,passwd-pcr7-file",
			Usage: "File from which to read password pcr7",
			Value: "passwd_pcr7.bin",
		},
		cli.StringFlag{
			Name:  "lp,production-pcr7-file,luks-pcr7-file",
			Usage: "File from which to read production pcr7",
			Value: "luks_pcr7.bin",
		},
		cli.IntFlag{
			Name:  "pv,policy-version",
			Usage: "Policy version",
			Value: 1,
		},
		cli.StringFlag{
			Name:  "pk,passwd-pubkey-file",
			Usage: "File from which to read password policy pubkey",
			Value: "passwd_pubkey.pem",
		},
		cli.StringFlag{
			Name:  "lk,luks-pubkey-file",
			Usage: "File from which read write luks policy pubkey",
			Value: "luks_pubkey.pem",
		},
	},
}

func doTpmPolicygen(ctx *cli.Context) error {
	return trust.TpmGenPolicy(ctx)
}

