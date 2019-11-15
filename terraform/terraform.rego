package terraform

deny {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    count(changes.change.after.name) > 30
}