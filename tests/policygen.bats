load helpers

function setup() {
	common_setup
	rm -rf "${BATS_TMPDIR}/passwd.out" "${BATS_TMPDIR}/luks.out"
	rm -rf "${BATS_TMPDIR}/luks_policy.out" "${BATS_TMPDIR}/passwd_policy.out"
}

function teardown() {
	common_teardown
	rm -rf "${BATS_TMPDIR}/passwd.out" "${BATS_TMPDIR}/luks.out"
	rm -rf "${BATS_TMPDIR}/luks_policy.out" "${BATS_TMPDIR}/passwd_policy.out"
}

@test "Generate a policy" {
	trust tpm-policy-gen --pcr7-tpm "${BATS_TEST_DIRNAME}/sample1/pcr7-tpm.bin" \
	    --pcr7-production "${BATS_TEST_DIRNAME}/sample1/pcr7-prod.bin" \
	    --passwd-policy-file "${BATS_TMPDIR}/passwd.out" \
	    --luks-policy-file "${BATS_TMPDIR}/luks.out" \
		--policy-version 0001
	diff "${BATS_TMPDIR}/passwd.out" "${BATS_TEST_DIRNAME}/sample1/passwd.policy"
	diff "${BATS_TMPDIR}/luks.out" "${BATS_TEST_DIRNAME}/sample1/luks.policy"
}

@test "Generate a policy using defaults" {
	current_dir=${PWD}; cd "${BATS_TMPDIR}"
	trust tpm-policy-gen --pcr7-tpm "${BATS_TEST_DIRNAME}/sample1/pcr7-tpm.bin" \
	    --pcr7-production "${BATS_TEST_DIRNAME}/sample1/pcr7-prod.bin"
	cd $current_dir
	diff "${BATS_TMPDIR}/passwd_policy.out" "${BATS_TEST_DIRNAME}/sample1/passwd.policy"
	diff "${BATS_TMPDIR}/luks_policy.out" "${BATS_TEST_DIRNAME}/sample1/luks.policy"
}
