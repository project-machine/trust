package trust

import (
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"os"
)

// genLuksPolicy creates a policy for reading the LUKS password
// while booted under a production key.
func genLuksPolicy(ctx *cli.Context) error {
	workd, err := os.MkdirTemp("", "lukspol")
	if err != nil {
		return errors.Wrapf(err, "Error creating tempdir")
	}
	defer os.RemoveAll(workd)

	sessName := filepath.Join(workd, "tpm_session_b")

	if err := RunCommand("tpm2_startauthsession", "-S", sessName); err != nil {
		return errors.Wrapf(err, "Failed creating auth session");
	}
	defer RunCommand("tpm2_flushcontext", sessName)

	cmd := []string{
		"tpm2_policypcr",
		"-S", sessName,
		"-l", "sha256:7",
		"-f", ctx.String("passwd-pcr7-file"),
	}
	if err := RunCommand(cmd...); err != nil {
		return errors.Wrapf(err, "Failed running policypcr")
	}

	cmd = []string{
		"tpm2_policynv", "-i-",
		 "-S", sessName,
		 TPM2IndexEAVersion.String(), "eq",
		 "-L", ctx.String("luks-policy-file"),
	}
	if err := runWithStdin(PolicyVersion.String(), cmd...); err != nil {
		return errors.Wrapf(err, "Failed running policynv")
	}

	return nil
}

func genPasswdPolicy(ctx *cli.Context) error {
	workd, err := os.MkdirTemp("", "passpol")
	if err != nil {
		return errors.Wrapf(err, "Error creating tempdir")
	}
	defer os.RemoveAll(workd)

	sessName := filepath.Join(workd, "tpm_session_a")

	if err := RunCommand("tpm2_startauthsession", "-S", sessName); err != nil {
		return errors.Wrapf(err, "Failed creating auth session");
	}
	defer RunCommand("tpm2_flushcontext", sessName)

	cmd := []string{
		"tpm2_policypcr",
		"-S", sessName,
		"-l", "sha256:7",
		"-f", ctx.String("passwd-pcr7-file"),
		"-L", ctx.String("passwd-policy-file"),
	}
	if err := RunCommand(cmd...); err != nil {
		return errors.Wrapf(err, "Failed running policypcr")
	}

	return nil
}

func TpmGenPolicy(ctx *cli.Context) error {
	if err := genLuksPolicy(ctx); err != nil {
		return err
	}
	if err := genPasswdPolicy(ctx); err != nil {
		return err
	}
	return nil
}
