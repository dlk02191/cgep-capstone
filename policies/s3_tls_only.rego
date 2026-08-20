# policies/s3_tls_only.rego
# METADATA
# title: HIPAA 164.312(e)(1) - Transmission Security (S3 TLS-only)
# description: "Every aws_s3_bucket must have an aws_s3_bucket_policy containing an explicit Deny on aws:SecureTransport = false."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: high
#   remediation: "Attach a bucket policy with Effect Deny, Principal *, s3:* on the bucket and /* ARNs, condition Bool aws:SecureTransport = false. See terraform/hardening.tf for the pattern."
package compliance.hipaa.tls_only

import rego.v1

# The rule fires (emits a violation) when ALL of these are true:
#   1. There is an aws_s3_bucket in the plan
#   2. There is NO aws_s3_bucket_policy that covers that bucket with:
#        - a statement whose Effect is "Deny"
#        - a condition on aws:SecureTransport

deny contains msg if {
	some bucket in buckets                    # condition 1
	not has_tls_deny(bucket)                  # condition 2
	msg := sprintf(
		"[164.312(e)(1)] %s: no bucket policy denying non-TLS requests (aws:SecureTransport). Remediation: attach an explicit Deny on aws:SecureTransport = false.",
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

has_tls_deny(bucket) if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket_policy"
	doc := json.unmarshal(r.values.policy)
	some stmt in doc.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"]
	policy_references_bucket(r.address, bucket.address)   # NEW: wiring check
}

policy_references_bucket(policy_addr, bucket_addr) if {
	some c in input.configuration.root_module.resources
	c.address == policy_addr
	some ref in c.expressions.bucket.references
	references_bucket(ref, bucket_addr)
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])