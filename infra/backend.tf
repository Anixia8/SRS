terraform {
  backend "gcs" {
    bucket = "srs-project-469414-tf-state"
    prefix = "llm4soc/terraform"
  }
}