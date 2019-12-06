# Example showing how to verify GCP changes proposed in a Terraform plan file using the Conftest Rego policy structure.
# See https://github.com/instrumenta/conftest
# The aim is to output an error message that tells the developer which policy has been violated by which GCP resource.
# And, to remove the error message duplication between the policies and the tests. 
# Note, this technique currently works in OPA but does NOT work in Conftest. See https://github.com/instrumenta/conftest/issues/169
package terraform

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