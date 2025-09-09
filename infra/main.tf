# Abilita API base
resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "serviceusage.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
  ])
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

# Abilita Vertex AI solo se serve
resource "google_project_service" "aiplatform" {
  count              = var.model_provider == "vertexai" ? 1 : 0
  project            = var.project_id
  service            = "aiplatform.googleapis.com"
  disable_on_destroy = false
}

# Artifact Registry (repo Docker)
resource "google_artifact_registry_repository" "repo" {
  location      = var.region
  repository_id = var.repo_id
  format        = "DOCKER"
  description   = "Repo per LLM4SOC"
  depends_on    = [google_project_service.apis]
}

# Service Account per Cloud Run
resource "google_service_account" "run_sa" {
  account_id   = "llm4soc-sa"
  display_name = "Cloud Run SA for LLM4SOC"
}

# Permesso Vertex AI al SA (se usi vertex)
resource "google_project_iam_member" "vertex_user" {
  count   = var.model_provider == "vertexai" ? 1 : 0
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.run_sa.email}"
}

# Servizio Cloud Run v2
resource "google_cloud_run_v2_service" "app" {
  name     = var.service_name
  location = var.region

  template {
    service_account = google_service_account.run_sa.email

    scaling {
      max_instance_count = var.max_instances
      min_instance_count = var.min_instances
    }

    containers {
      image = var.image
      
      env {
          name  = "LLM_MODEL"
          value = "gemini-1.5-flash-002"
      }

      env {
        name  = "VERTEX_LOCATION"
        value = var.vertex_location  # resta agganciato alla tua variabile
      }
      
 
      ports {
        container_port = var.port
      }

      resources {
        cpu_idle = true
        limits = {
          cpu    = tostring(var.cpu)
          memory = var.memory
        }
      }

      # ENV comuni
      env {
        name  = "MODEL_PROVIDER"
        value = var.model_provider
      }

      # ENV Vertex AI (selezionate via dynamic)
      dynamic "env" {
        for_each = var.model_provider == "vertexai" ? {
          VERTEX_LOCATION = var.vertex_location
          LLM_MODEL       = var.llm_model
        } : {}
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  ingress = "INGRESS_TRAFFIC_ALL"

  # dipendenze statiche (no concat)
  depends_on = [
    google_artifact_registry_repository.repo,
    google_service_account.run_sa
  ]
}

# Accesso pubblico (se vuoi URL pubblico)
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  count    = var.allow_unauthenticated ? 1 : 0
  name     = google_cloud_run_v2_service.app.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}