terraform {
  backend "s3" {
    bucket = "tcs-engineering-tfstatestore-bucket-5362"
    key    = "tfstates"
    region = "ca-central-1"
  }
}
