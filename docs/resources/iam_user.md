---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "minio_iam_user Resource - terraform-provider-minio"
subcategory: ""
description: |-
  
---

# minio_iam_user (Resource)



## Example Usage

```terraform
resource "minio_iam_user" "test" {
   name = "test"
   force_destroy = true
   tags = {
    tag-key = "tag-value"
  }
}

output "test" {
  value = "${minio_iam_user.test.id}"
}

output "status" {
  value = "${minio_iam_user.test.status}"
}

output "secret" {
  value = "${minio_iam_user.test.secret}"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **name** (String) Access Key of the user
- **secret** (String, Sensitive) Secret Key of the user

### Optional

- **disable_user** (Boolean) Disable user
- **force_destroy** (Boolean) When deleting user, proceed even if it has non-Terraform-managed IAM access keys
- **id** (String) The ID of this resource.
- **tags** (Map of String)

### Read-Only

- **status** (String)


