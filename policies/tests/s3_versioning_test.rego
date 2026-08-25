# policies/tests/s3_versioning_test.rego
package compliance.hipaa.s3_versioning_test
import rego.v1
import data.compliance.hipaa.s3_versioning
# Fixture 1: compliant — bucket + wired versioning with status Enabled
compliant := {
        "planned_values": {"root_module": {"resources": [
                {
                        "address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket",
                        "values": {},
                },
                {
                        "address": "aws_s3_bucket_versioning.uploads", "type": "aws_s3_bucket_versioning",
                        "values": {"versioning_configuration": [{"status": "Enabled"}]},
                },
        ]}},
        "configuration": {"root_module": {"resources": [{
                "address": "aws_s3_bucket_versioning.uploads", "type": "aws_s3_bucket_versioning",
                "expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
        }]}},
}
# Fixture 2: gap open — bucket with no versioning resource at all
no_versioning := {
        "planned_values": {"root_module": {"resources": [{
                "address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket",
                "values": {},
        }]}},
        "configuration": {"root_module": {"resources": []}},
}
# Fixture 3: the sneaky one — wired versioning resource with status Suspended
suspended := {
        "planned_values": {"root_module": {"resources": [
                {
                        "address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket",
                        "values": {},
                },
                {
                        "address": "aws_s3_bucket_versioning.uploads", "type": "aws_s3_bucket_versioning",
                        "values": {"versioning_configuration": [{"status": "Suspended"}]},
                },
        ]}},
        "configuration": {"root_module": {"resources": [{
                "address": "aws_s3_bucket_versioning.uploads", "type": "aws_s3_bucket_versioning",
                "expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
        }]}},
}
test_compliant_passes if {
        count(s3_versioning.deny) == 0 with input as compliant
}
test_missing_versioning_fails if {
        some msg in s3_versioning.deny with input as no_versioning
        contains(msg, "164.308(a)(7)")
}
test_suspended_versioning_fails if {
        some msg in s3_versioning.deny with input as suspended
        contains(msg, "164.308(a)(7)")
}
