package lib

type Truststore interface {
	Provision(certPath, keyPath string) error
	InitrdSetup() error
	PreInstall() error
}
