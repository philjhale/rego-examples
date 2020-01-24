# Example showing how to verify GCP changes proposed in a Terraform plan file using the Conftest Rego policy structure.

# To verify the tests using Conftest execute
# docker run --rm -v $(pwd):/project instrumenta/conftest verify --policy /project --data /project/error-message.json

# To test input.json using Conftest execute
# docker run --rm -v $(pwd):/project instrumenta/conftest test /project/input.json --policy /project --data /project/error-message.json

package main

deny[msg] {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    count(changes.change.after.name) > 30
    msg = sprintf(data.error_messages.project_name_too_long_msg, [changes.change.after.name])
}

deny[msg] {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    labels := changes.change.after.labels[_]
    not re_match("^[a-z0-9]{1,10}$", labels) 
    msg = sprintf(data.error_messages.project_label_invalid_msg, [labels])
}

deny[msg] {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    not changes.change.after.labels
    msg = sprintf(data.error_messages.project_required_label_env_missing_msg, ["env"])
}

required_labels = ["env", "team"]
deny[msg] {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    required_label = required_labels[_]
    not changes.change.after.labels[required_label]
    msg = sprintf(data.error_messages.project_required_label_missing_msg, [concat(",", required_labels)])
}