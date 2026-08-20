# policies/tests/s3_tls_only_test.rego
package compliance.hipaa.tls_only_test

import rego.v1

import data.compliance.hipaa.tls_only

# Fixture 1: compliant — bucket + wired policy with a SecureTransport Deny
compliant := {
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket",
			"values": {},
		},
		{
			"address": "aws_s3_bucket_policy.tls_only", "type": "aws_s3_bucket_policy",
			"values": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"},
		},
	]}},
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.tls_only", "type": "aws_s3_bucket_policy",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
	}]}},
}

# Fixture 2: gap open — bucket with no bucket policy at all
no_policy := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket",
		"values": {},
	}]}},
	"configuration": {"root_module": {"resources": []}},
}

# Fixture 3: the sneaky one — a wired bucket policy that is NOT a TLS deny
wrong_policy := {
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket",
			"values": {},
		},
		{
			"address": "aws_s3_bucket_policy.deny_delete", "type": "aws_s3_bucket_policy",
			"values": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:DeleteBucket\",\"Resource\":\"*\"}]}"},
		},
	]}},
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.deny_delete", "type": "aws_s3_bucket_policy",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
	}]}},
}

test_compliant_passes if {
	count(tls_only.deny) == 0 with input as compliant
}

test_missing_policy_fails if {
	some msg in tls_only.deny with input as no_policy
	contains(msg, "164.312(e)(1)")
}

test_non_tls_policy_fails if {
	some msg in tls_only.deny with input as wrong_policy
	contains(msg, "164.312(e)(1)")
}