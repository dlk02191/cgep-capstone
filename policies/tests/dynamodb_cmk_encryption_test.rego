# policies/tests/dynamodb_cmk_encryption_test.rego
package compliance.hipaa.dynamodb_cmk_test

import rego.v1

import data.compliance.hipaa.dynamodb_cmk

# Fixture 1: compliant — table with server_side_encryption enabled, referencing an owned key
compliant := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake", "type": "aws_dynamodb_table",
		"values": {},
	}]}},
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {
			"server_side_encryption": [{
				"enabled": {"constant_value": true},
				"kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
			}],
		},
	}]}},
}

# Fixture 2: gap open — table with no server_side_encryption block at all. This is GAP-02 as shipped.
no_sse := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake", "type": "aws_dynamodb_table",
		"values": {},
	}]}},
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {},
	}]}},
}

# Fixture 3: the decoy — encryption enabled, but no kms_key_arn. That means the AWS-managed
# aws/dynamodb key: encrypted, yes, but not under customer custody.
aws_managed_key := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake", "type": "aws_dynamodb_table",
		"values": {},
	}]}},
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {
			"server_side_encryption": [{
				"enabled": {"constant_value": true},
			}],
		},
	}]}},
}

test_cmk_encrypted_passes if {
	count(dynamodb_cmk.deny) == 0 with input as compliant
}

test_missing_sse_fails if {
	some msg in dynamodb_cmk.deny with input as no_sse
	contains(msg, "164.312(a)(2)(iv)")
}

test_aws_managed_key_fails if {
	some msg in dynamodb_cmk.deny with input as aws_managed_key
	contains(msg, "164.312(a)(2)(iv)")
}