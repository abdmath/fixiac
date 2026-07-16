resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-test-bucket-12345"
}

resource "aws_s3_bucket_public_access_block" "my_bucket_pab" {
  bucket                  = aws_s3_bucket.my_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
