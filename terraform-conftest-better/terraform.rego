package terraform

deny[{"name": name, "msg": msg}] {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    count(changes.change.after.name) > 30
    msg = "Project name too long"
    name = input.resource_changes[_].change.after.name
}

deny[{"name": name, "msg": msg}] {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    labels := changes.change.after.labels[_]
    not re_match("^[a-z0-9]{1,10}$", labels) 
    msg = "Project labels are invalid"
    name = input.resource_changes[_].change.after.name
}