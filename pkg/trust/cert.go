package trust

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Check that the product cert was signed by the global puzzleos cert
// This version can be used by outside callers, like atomix extract-soci
// Note that this version does not verify product pid.
func VerifyCert(cert []byte, caPath string) error {
	paths := []string{
		"/factory/secure/manifestCA.pem",
		"/factory/secure/layerCA.pem",
		"/manifestCA.pem",
		"/layerCA.pem",
	}
	if caPath != "" {
		paths = append(paths, caPath)
	}

	var rootBytes []byte
	var err error
	for _, p := range paths {
		rootBytes, err = os.ReadFile(p)
		if err == nil || !os.IsNotExist(err) {
			break
		}

	}
	if err != nil {
		return fmt.Errorf("Failed reading OCI signing CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootBytes) {
		return fmt.Errorf("Failed adding cert from OCI signing CA")
	}

	block, _ := pem.Decode(cert)
	if block == nil {
		return fmt.Errorf("Failed to parse manifest-signing certificate PEM: %w", err)
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("Failed reading certificate from manifest: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err = parsedCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("OCI signing certificate verification failed: %w", err)
	}
	return nil
}

// VerifyManifest checks that @contents is signed by 
func VerifyManifest(contents []byte, sigPath, certPath, caPath string) error {
	xtract := []string{"openssl", "x509", "-in", certPath, "-pubkey", "-noout"}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("Failed reading manifest cert (%q): %w", certPath, err)
	}
	pubout, _, err := RunWithStdall(string(cert), xtract...)

	tmpd, err := os.MkdirTemp("", "pubkey")
	if err != nil {
		return fmt.Errorf("Failed creating a tempdir: %w", err)
	}
	defer os.RemoveAll(tmpd)
	keyPath := filepath.Join(tmpd, "pub.key")
	err = os.WriteFile(keyPath, []byte(pubout), 0600)
	if err != nil {
		return fmt.Errorf("Failed writing out public key: %w", err)
	}

	err = VerifyCert(cert, caPath)
	if err != nil {
		return fmt.Errorf("Manifest certificate does not match the CA: %w", err)
	}

	cmd := []string{"openssl", "dgst", "-sha256", "-verify", keyPath,
		"-signature", sigPath}
	// Pass the manifest text (whose signature we are verifying) in over
	// stdin to avoid a TOCTTOU between manifest reads.
	stdout, stderr, err := RunWithStdall(string(contents), cmd...)
	if err != nil {
		errmsg := "Failed verifying manifest signature:\nStdout: %v\nStderr: %v\nError: %w"
		return fmt.Errorf(errmsg, err, stdout, stderr)
	}

	return nil
}

// Sign: sign a file
// Sign the contents of @sourcePath using the key at @keyPath,
// storing the result in the file called @signedpath
func Sign(sourcePath, signedPath, keyPath string) error {
	args := []string{"openssl", "dgst", "-sha256",
		"-sign", keyPath,
		"-out", signedPath,
		sourcePath}
	output, err := Run(args...)
	if err != nil {
		return fmt.Errorf("Signing error: %w\nOutput: %s\n", err, output)
	}

	return nil
}
