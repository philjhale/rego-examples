package terraform

test_project_name_allowed {
    not deny[""] with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project" } } }] }
}

test_project_name_too_long_denied {
    deny[sprintf(data.error_messages.project_name_too_long_msg, [input.resource_changes[_].change.after.name])] with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project whose name is too long" } } },{ "type": "google_project", "change": { "after": { "name": "Test project whose name is too long 2" } } }] }
}

test_project_label_contains_hypen_denied {
    deny[invalid_label_msg] with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project", "labels": { "env": "dev!" } } } }] }
}

test_project_label_too_long_denied {
    deny[invalid_label_msg] with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project", "labels": { "env": "01234567890" } } } }] }
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