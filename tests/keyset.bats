load helpers

function setup() {
	common_setup
}

function teardown() {
	common_teardown
}

@test "Create snakeoil keyset" {
	trust keyset add snakeoil
	[ -d "$MDIR/trust/keys/snakeoil/.git" ]
	trust keyset list | grep snakeoil
}

@test "Create new keysets" {
	trust keyset add zomg
	trust keyset add --org "My organization" homenet
	cnt=$(trust keyset list | wc -l)
	[ $cnt -eq 2 ]
}
