provider "google" {
  credentials = file("<PATH-TO-YOUR-SERVICE-ACCOUNT-KEY>.json")
  project     = "<YOUR-PROJECT-ID>"
  region      = "us-central1"
}

resource "google_compute_network" "vpc_network" {
  name = "vulnerable-network"
}

resource "google_storage_bucket" "vulnerable_bucket" {
  name     = "vulnerable-bucket-${random_id.bucket_suffix.hex}"
  location = "US"
}

resource "random_id" "bucket_suffix" {
  byte_length = 8
}

resource "google_compute_instance" "vulnerable_vm" {
  name         = "vulnerable-vm"
  machine_type = "f1-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-9"
    }
  }

  network_interface {
    network = google_compute_network.vpc_network.name
    access_config {
      // Ephemeral public IP
    }
  }
}

resource "google_sql_database_instance" "vulnerable_sql_instance" {
  name     = "vulnerable-sql-instance"
  region   = "us-central1"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      require_ssl = false
    }
  }
}

resource "google_container_cluster" "vulnerable_cluster" {
  name     = "vulnerable-cluster"
  location = "us-central1"

  remove_default_node_pool = true
  initial_node_count = 1

  node_config {
    machine_type = "n1-standard-1"
  }
}
