variable "project_id" { type = string }

variable "region" {
  type    = string
  default = "europe-west8"
}

variable "vertex_location" {
  type    = string
  default = "europe-west1"
}

variable "repo_id" {
  type    = string
  default = "llm4soc"
}

variable "service_name" {
  type    = string
  default = "llm4soc"
}

variable "image" { type = string } # URI completo dell'immagine Docker

variable "model_provider" {
  type    = string
  default = "vertexai" # vertexai | openai | ollama
}

variable "llm_model" {
  type    = string
  default = "gemini-1.5-flash-002"
}

variable "openai_model" {
  type    = string
  default = "gpt-4o-mini"
}

variable "openai_api_key" {
  type      = string
  default   = null
  sensitive = true
}

variable "cpu" {
  type    = number
  default = 2
}

variable "memory" {
  type    = string
  default = "2Gi"
}

variable "port" {
  type    = number
  default = 8080
}

variable "max_instances" {
  type    = number
  default = 1
}

variable "min_instances" {
  type    = number
  default = 0
}

variable "allow_unauthenticated" {
  type    = bool
  default = true
}