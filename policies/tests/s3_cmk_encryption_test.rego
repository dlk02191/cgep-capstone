# policies/tests/s3_cmk_encryption_test.rego
package compliance.hipaa.s3_cmk_test

import rego.v1

import data.compliance.hipaa.s3_cmk

# Fixture 1: compliant — bucket + wired encryption config, aws:kms, referencing an owned key
compliant := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket",
		"values": {},
	}]}},
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
			"rule": [{
				"apply_server_side_encryption_by_default": [{
					"sse_algorithm": {"constant_value": "aws:kms"},
					"kms_master_key_id": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
				}],
			}],
		},
	}]}},
}

# Fixture 2: gap open — bucket with no encryption configuration at all
no_config := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket",
		"values": {},
	}]}},
	"configuration": {"root_module": {"resources": []}},
}

# Fixture 3: the decoy — wired encryption config, but AES256 (SSE-S3), no key. This is GAP-01 itself.
sse_s3_only := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket",
		"values": {},
	}]}},
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
			"rule": [{
				"apply_server_side_encryption_by_default": [{
					"sse_algorithm": {"constant_value": "AES256"},
				}],
			}],
		},
	}]}},
}

test_cmk_encrypted_passes if {
	count(s3_cmk.deny) == 0 with input as compliant
}

test_missing_config_fails if {
	some msg in s3_cmk.deny with input as no_config
	contains(msg, "164.312(a)(2)(iv)")
}

test_sse_s3_fails if {
	some msg in s3_cmk.deny with input as sse_s3_only
	contains(msg, "164.312(a)(2)(iv)")
}