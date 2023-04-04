load helpers

function setup() {
	common_setup
}

function teardown() {
	common_teardown
}

@test "Keyset creation creates default project" {
	trust keyset add zomg
	trust project list zomg | grep default
}

@test "Create project" {
	trust keyset add zomg
	trust project add zomg newproject
	trust project list zomg | grep newproject
	cnt=$(trust project list zomg | wc -l)
	[ $cnt -eq 2 ]
}
