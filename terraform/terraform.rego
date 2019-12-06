# Example showing how to verify GCP changes proposed in a Terraform plan file
package terraform

# GCP project name must be less than 30 characters
deny {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    count(changes.change.after.name) > 30
}