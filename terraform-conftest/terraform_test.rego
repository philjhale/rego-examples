package main

# empty and no_violations idea borrowed from https://github.com/instrumenta/conftest/blob/master/examples/kubernetes/policy/base_test.rego

empty(value) {
  count(value) == 0
}

no_violations {
  empty(deny)
}

test_project_allowed {
    no_violations 
    with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project", "labels": { "env": "dev", "team": "stuff" } } } }] }
}

test_project_name_too_long_denied {
    deny[sprintf(data.error_messages.project_name_too_long_msg, [input.resource_changes[_].change.after.name])] 
    with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project whose name is too long" } } },{ "type": "google_project", "change": { "after": { "name": "Test project whose name is too long 2" } } }] }
}

test_project_label_contains_hypen_denied {
    deny[sprintf(data.error_messages.project_label_invalid_msg, ["dev!"])] 
    with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project", "labels": { "env": "dev!" } } } }] }
}

test_project_label_too_long_denied {
    deny[sprintf(data.error_messages.project_label_invalid_msg, ["01234567890"])] 
    with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project", "labels": { "env": "01234567890" } } } }] }
}

test_missing_env_label_denied {
    deny[sprintf(data.error_messages.project_required_label_env_missing_msg, ["env"])] 
    with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project" } } }] }
}

test_missing_team_label_denied {
    deny[sprintf(data.error_messages.project_required_label_missing_msg, ["Test project", "env,team"])] 
    with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project", "labels": { "env": "dev" } } } }] }
}

test_invalid_team_label_denied {
    deny[sprintf(data.error_messages.project_required_label_missing_msg, ["Test project", "env,team"])] 
    with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project", "labels": { "env": "dev" } } } }] }
}


# Sample Terraform plan
#"resource_changes": [
#  {
#     "address": "module.test.google_project.main",
#     "module_address": "module.test",
#     "mode": "managed",
#     "type": "google_project",
#     "name": "main",
#     "provider_name": "google",
#     "change": {
#         "before": null,
#         "after": {
#             "auto_create_network": true,
#             "billing_account": "1234-5678",
#             "labels": {,
#                 "env": "dev",
#                 "team": "my team"
#             },
#             "name": "Test project",
#             "org_id": "1234"
#         }
#     }
# }
#]