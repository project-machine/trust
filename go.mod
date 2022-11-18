module github.com/project-machine/trust

require (
	github.com/anuvu/disko v0.0.11
	github.com/apex/log v1.9.0
	github.com/canonical/go-tpm2 v0.0.0-20220823192114-7a7993f0fa1f
	github.com/google/uuid v1.3.0
	github.com/plus3it/gorecurcopy v0.0.1
	github.com/urfave/cli v1.22.5
)

require (
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rekby/gpt v0.0.0-20200219180433-a930afbc6edc // indirect
	github.com/rekby/mbr v0.0.0-20190325193910-2b19b9cdeebc // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
)

require (
	github.com/canonical/go-sp800.108-kdf v0.0.0-20210314145419-a3359f2d21b9 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0-20190314233015-f79a8a8ca69d // indirect
	github.com/jsipprell/keyctl v1.0.4
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f // indirect
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898 // indirect
)

replace github.com/jsipprell/keyctl => github.com/hallyn/keyctl v1.0.4-0.20211206210026-67b989e45620

go 1.18
