output "service_url" {
  value       = google_cloud_run_v2_service.app.uri
  description = "URL pubblico dell'app"
}