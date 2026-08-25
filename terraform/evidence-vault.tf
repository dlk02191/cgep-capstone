# Evidence vault: Object Lock bucket for signed pipeline evidence
# Lab 2.5 pattern, adapted: CMK encryption per capstone brief,
# GOVERNANCE mode (sandbox teardown), separate key from PHI CMK.


resource "aws_kms_key" "evidence" {
  description             = "CMK for evidence vault encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7 # sandbox value; production = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/acme-health-mgmt"
          }
        }
      },
    ]
  })

  tags = {
    DataClass = "evidence"
  }
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/acme-health-evidence-${random_id.suffix.hex}"
  target_key_id = aws_kms_key.evidence.key_id
}

# --- The vault ---
resource "aws_s3_bucket" "evidence_vault" {
  bucket              = "acme-health-evidence-vault-${random_id.suffix.hex}"
  object_lock_enabled = true # MUST be set at creation; no retrofit path

  tags = {
    DataClass = "evidence"
  }
}

resource "aws_s3_bucket_versioning" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  versioning_configuration {
    status = "Enabled" # Object Lock requires versioning
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    default_retention {
      mode = "GOVERNANCE" # defended: sandbox teardown; COMPLIANCE in production
      days = 30           # covers submission-to-grading window
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence_vault]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_vault" {
  bucket                  = aws_s3_bucket.evidence_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Refuse bucket deletion from anyone except account root (Lab 2.5 pattern) ---
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
    policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyBucketDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteBucket"
        Resource  = aws_s3_bucket.evidence_vault.arn
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidence_vault.arn,
          "${aws_s3_bucket.evidence_vault.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })
}

output "evidence_vault_name" {
  value = aws_s3_bucket.evidence_vault.bucket
}