# policies/s3_versioning.rego
# METADATA
# title: HIPAA 164.308(a)(7) - Contingency Plan (S3 versioning)
# description: "Every aws_s3_bucket must have a wired aws_s3_bucket_versioning resource with status Enabled."
# custom:
#   framework: hipaa
#   controls:
#     - "164.308(a)(7)"
#   severity: medium
#   remediation: "Add an aws_s3_bucket_versioning resource referencing the bucket with versioning_configuration status = Enabled. See terraform/hardening.tf for the pattern."
package compliance.hipaa.s3_versioning
import rego.v1

deny contains msg if {
        some bucket in buckets
        not has_versioning_enabled(bucket)
        msg := sprintf(
                "[164.308(a)(7)] %s: no versioning resource with status Enabled wired to this bucket. Remediation: add aws_s3_bucket_versioning with versioning_configuration status = Enabled.",
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

has_versioning_enabled(bucket) if {
        some r in input.planned_values.root_module.resources
        r.type == "aws_s3_bucket_versioning"
        some cfg in r.values.versioning_configuration
        cfg.status == "Enabled"
        versioning_references_bucket(r.address, bucket.address)
}

versioning_references_bucket(versioning_addr, bucket_addr) if {
        some c in input.configuration.root_module.resources
        c.address == versioning_addr
        some ref in c.expressions.bucket.references
        references_bucket(ref, bucket_addr)
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
