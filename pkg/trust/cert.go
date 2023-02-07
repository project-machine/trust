package trust

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// VerifyCert checks that the product cert was signed by the
// global puzzleos cert. This version can be used by outside
// callers, like atomix extract-soci. Note that this version
// does not verify product pid.
func VerifyCert(parsedCert *x509.Certificate, caPath string) error {
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
	// Get the cert and extract the public key
	var parsedCert *x509.Certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("Failed reading manifest cert (%q): %w", certPath, err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("Failed to decode manifest cert (%q)", certPath)
	}
	parsedCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("Failed parsing manifest cert (%q): %w", certPath, err)
	}
	rsaPublicKey := parsedCert.PublicKey.(*rsa.PublicKey)

	// Verify the chain of trust
	err = VerifyCert(parsedCert, caPath)
	if err != nil {
		return fmt.Errorf("Manifest certificate does not match the CA: %w", err)
	}

	// Get the signature
	signature, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("Failed reading signature (%q): %w", sigPath, err)
	}

	// Verify signature
	msghash := sha256.Sum256(contents)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, msghash[:], signature)
	if err != nil {
		return fmt.Errorf("Failed verifying manifest signature: %w", err)
	}

	return nil
}

// Sign signs a file
// Sign the contents of @sourcePath using the key at @keyPath,
// storing the result in the file called @signedpath
func Sign(sourcePath, signedPath, keyPath string) error {
	// Get the key to use for signing
	privKey, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("Failed reading (%q): %w", keyPath, err)
	}
	pemBlock, _ := pem.Decode(privKey)
	if pemBlock == nil {
		return fmt.Errorf("Failed to decode key: (%q)", keyPath)
	}
	pkcsKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("Failed parsing key, (%q): %w", keyPath, err)
	}

	// Hash the data @sourcePath
	msg, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("Failed reading (%q): %w", sourcePath, err)
	}
	msghash := sha256.Sum256(msg)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(nil, pkcsKey.(*rsa.PrivateKey), crypto.SHA256, msghash[:])
	if err != nil {
		return fmt.Errorf("Failed signing hash of (%q): %w", sourcePath, err)
	}

	// Write the signature to signedPath
	err = os.WriteFile(signedPath, signature, 0640)
	if err != nil {
		return fmt.Errorf("Failed writing signature to (%q): %w", signedPath, err)
	}

	return nil
}
