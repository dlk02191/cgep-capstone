# policies/dynamodb_cmk_encryption.rego
# METADATA
# title: HIPAA 164.312(a)(2)(iv) - Encryption at Rest (DynamoDB customer CMK)
# description: "Every aws_dynamodb_table must have server_side_encryption enabled with kms_key_arn referencing a key owned by this Terraform."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: "Add a server_side_encryption block with enabled = true and kms_key_arn referencing an aws_kms_key resource. See terraform/main.tf."
package compliance.hipaa.dynamodb_cmk

import rego.v1

# The rule fires when ALL of these are true:
#   1. There is an aws_dynamodb_table in the plan
#   2. There is NO server_side_encryption block on that table which:
#        - has enabled = true
#        - references an aws_kms_key resource in this plan (custody)

deny contains msg if {
	some table in tables
	not has_cmk_encryption(table)
	msg := sprintf(
		"[164.312(a)(2)(iv)] %s: server_side_encryption is missing, disabled, or not using a customer-managed key. Remediation: add server_side_encryption { enabled = true, kms_key_arn = <aws_kms_key>.arn }.",
		[table.address],
	)
}

tables contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_dynamodb_table"
}

tables contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
	r.type == "aws_dynamodb_table"
}

has_cmk_encryption(table) if {
	some c in input.configuration.root_module.resources
	c.type == "aws_dynamodb_table"
	c.address == table.address
	some sse in c.expressions.server_side_encryption
	sse.enabled.constant_value == true
	some ref in sse.kms_key_arn.references
	startswith(ref, "aws_kms_key.")
}