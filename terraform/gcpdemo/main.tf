provider "google" {
  credentials = file("<YOUR-CREDENTIALS-FILE>.json")
  project     = "<YOUR-PROJECT-ID>"
  region      = "us-central1"
}

resource "google_compute_network" "vpc_network" {
  name = "terraform-network"
}

resource "google_compute_firewall" "firewall" {
  name    = "terraform-firewall"
  network = google_compute_network.vpc_network.name

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_instance" "default" {
  name         = "terraform-instance"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-9"
    }
  }

  network_interface {
    network = google_compute_network.vpc_network.name
    access_config {
      // Ephemeral IP
    }
  }

  metadata_startup_script = <<-EOT
    #!/bin/bash
    sudo apt-get update
    sudo apt-get install -y nginx
  EOT
}

resource "google_sql_database_instance" "default" {
  name     = "terraform-sql-instance"
  region   = "us-central1"
  database_version = "POSTGRES_12"

  settings {
    tier = "db-f1-micro"
  }
}

resource "google_container_cluster" "primary" {
  name     = "terraform-cluster"
  location = "us-central1"

  remove_default_node_pool = true
  initial_node_count       = 1
}

resource "google_container_node_pool" "primary_preemptible_nodes" {
  name       = "terraform-nodes"
  location   = "us-central1"
  cluster    = google_container_cluster.primary.name
  node_count = 1

  node_config {
    preemptible  = true
    machine_type = "e2-micro"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}

resource "google_storage_bucket" "terraform_bucket" {
  name          = "terraform-test-bucket-${random_id.bucket_suffix.hex}"
  location      = "US"
  force_destroy = true
  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 2
}
