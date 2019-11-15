package terraform

test_project_name_allowed {
    not deny with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project" } } }] }
}

test_project_name_too_long_denied {
    deny with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project whos name is too long" } } }] }
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