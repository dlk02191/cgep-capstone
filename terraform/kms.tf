# GAP-01/GAP-02 dependency: CMK for PHI at rest.
# HIPAA 164.312(a)(2)(iv) — encryption under a key the covered entity controls.

resource "aws_kms_key" "phi" {
  description             = "CMK for Acme Health PHI at rest (uploads bucket, intake table)"
  enable_key_rotation     = true # annual rotation; limits how long compromised key material is useful
  deletion_window_in_days = 7 # sandbox value; production would use 30
}

resource "aws_kms_alias" "phi" {
  name          = "alias/acme-health-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}