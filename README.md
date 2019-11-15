# rego-examples

[Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) playground.

To run the tests.
```
docker run -v $PWD:/example openpolicyagent/opa test example/[path] -v
```

# Testing rules that define set documents

The following rule evaluates to a set document not a boolean document. If it were defined `deny { ... }` it would evaluate to a boolean document.

```
deny[msg] {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    count(changes.change.after.name) > 30
    msg = "Project name too long"
}
```

And an associated test.
```
test_project_name_too_long_denied {
    deny["Project name too long"] with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project whose name is too long" } } }] }
}
```

It's important to remember that `deny[msg]` returns a *set document*. If you evaluate the rule with the input in the test using the [Rego playground](https://play.openpolicyagent.org/) the output is:
```
{
    "deny": [
        "Project name too long"
    ]
}
```

What happens if you add two projects to the input?
```
test_project_name_too_long_denied {
    deny[project_name_too_long_msg] with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project whose name is too long" } } }, { "type": "google_project", "change": { "after": { "name": "Test project whose name is too long the sequel" } } }] }
}
```

Does this change the set document which is output? No, because sets are collections of unique values.

What happens if the `msg` includes the name of the project?
```
deny[msg] {
    changes := input.resource_changes[_] 
    changes.type == "google_project" 
    count(changes.change.after.name) > 30
    msg = input.resource_changes[_].change.after.name
}

test_project_name_too_long_denied {
    deny[input.resource_changes[_].change.after.name] with input as { "resource_changes": [{ "type": "google_project", "change": { "after": { "name": "Test project whose name is too long" } } },{ "type": "google_project", "change": { "after": { "name": "Test project whose name is too long 2" } } }] }
}
```

Does set change the evaluation of the set document? Yes.
```
{
    "deny": [
        "Test project whose name is too long",
        "Test project whose name is too long 2"
    ]
}
```