package main

import (
	"errors"
	"github.com/urfave/cli"
	"github.com/project-machine/trust/pkg/trust"
)

var tpmPolicyGenCmd = cli.Command{
	Name:   "tpm-policy-gen",
	Usage:  "Generate tpm policy for a keyset",
	Action: doTpmPolicygen,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "pf, passwd-policy-file",
			Usage: "File to which to write password policy",
			Value: "passwd_policy.out",
		},
		cli.StringFlag{
			Name:  "lf, luks-policy-file",
			Usage: "File to which to write luks policy",
			Value: "luks_policy.out",
		},
		cli.StringFlag{
			Name:  "pcr7-tpm",
			Usage: "File from which to read uki-tpm pcr7 value",
		},
		cli.StringFlag{
			Name:  "pcr7-production",
			Usage: "File from which to read uki-production pcr7 value",
		},
		cli.StringFlag{
			Name:  "pv, policy-version",
			Usage: "A four digit policy version, i.e. 0001",
			Value: "0001",
		},
	},
}

func doTpmPolicygen(ctx *cli.Context) error {
	args := ctx.Args()
	if len(args) != 0 {
		return errors.New("Usage: extra arguments")
	}

	pData := trust.PolicyData{
		Pcr7Prod: ctx.String("pcr7-production"),
		Pcr7Tpm: ctx.String("pcr7-tpm"),
		LuksOutFile: ctx.String("luks-policy-file"),
		PasswdOutFile: ctx.String("passwd-policy-file"),
		PolicyVersion: ctx.String("policy-version"),
	}

	return trust.TpmGenPolicy(pData)
}
