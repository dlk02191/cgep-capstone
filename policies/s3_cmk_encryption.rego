# policies/s3_cmk_encryption.rego
# METADATA
# title: HIPAA 164.312(a)(2)(iv) - Encryption at Rest (S3 customer CMK)
# description: "Every aws_s3_bucket must have a wired aws_s3_bucket_server_side_encryption_configuration using aws:kms with a key owned by this Terraform."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = \"aws:kms\" and kms_master_key_id referencing an aws_kms_key resource. See terraform/hardening.tf."
package compliance.hipaa.s3_cmk

import rego.v1

# The rule fires when ALL of these are true:
#   1. There is an aws_s3_bucket in the plan
#   2. There is NO encryption configuration for that bucket which:
#        - is wired to the bucket (reference match)
#        - uses sse_algorithm "aws:kms"
#        - references an aws_kms_key resource in this plan (custody)

deny contains msg if {
	some bucket in buckets
	not has_cmk_encryption(bucket)
	msg := sprintf(
		"[164.312(a)(2)(iv)] %s: no server-side encryption configuration using aws:kms with a customer-managed key. Remediation: add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = \"aws:kms\" referencing an aws_kms_key.",
		[bucket.address],
	)
}

buckets contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket"
}

buckets contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
	r.type == "aws_s3_bucket"
}

has_cmk_encryption(bucket) if {
	some c in input.configuration.root_module.resources
	c.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in c.expressions.bucket.references
	references_bucket(ref, bucket.address)
	uses_kms_algorithm(c)
	references_customer_key(c)
}

uses_kms_algorithm(c) if {
	some rule in c.expressions.rule
	rule.apply_server_side_encryption_by_default[0].sse_algorithm.constant_value == "aws:kms"
}

references_customer_key(c) if {
	some rule in c.expressions.rule
	some ref in rule.apply_server_side_encryption_by_default[0].kms_master_key_id.references
	startswith(ref, "aws_kms_key.")
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])