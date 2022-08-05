terraform {
  backend "s3" {
    bucket = "tcs-engineering-tfstatestore-bucket-5362"
    key    = "tfstates/acqa-repo1-aws-tf12-part1-no-name.tfstate"
    region = "ca-central-1"
  }
}
