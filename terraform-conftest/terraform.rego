package terraform

deny[msg] {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    count(changes.change.after.name) > 30
    msg = sprintf(data.error_messages.project_name_too_long_msg, [changes.change.after.name])
}

invalid_label_msg := "Project labels must be between 1 and 20 characters long and must only include lower case letters and numbers"
deny[msg] {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    labels := changes.change.after.labels[_]
    not re_match("^[a-z0-9]{1,10}$", labels) 
    msg = invalid_label_msg
}