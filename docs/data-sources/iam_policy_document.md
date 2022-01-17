---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "minio_iam_policy_document Data Source - terraform-provider-minio"
subcategory: ""
description: |-
  
---

# minio_iam_policy_document (Data Source)



## Example Usage

```terraform
data "minio_iam_policy_document" "example" {
  statement {
    sid = "1"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
    ]
    resources = [
      "arn:aws:s3:::*",
    ]
  }

  statement {
    actions = [
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::state-terraform-s3",
    ]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        "",
        "home/",
      ]
    }
  }

  statement {
    actions = [
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::state-terraform-s3",
      "arn:aws:s3:::state-terraform-s3/*",
    ]
  }
}

resource "minio_iam_policy" "test_policy" {
  name      = "state-terraform-s3"
  policy    = data.minio_iam_policy_document.example.json
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **id** (String) The ID of this resource.
- **override_json** (String)
- **policy_id** (String)
- **source_json** (String)
- **statement** (Block List) (see [below for nested schema](#nestedblock--statement))
- **version** (String)

### Read-Only

- **json** (String)

<a id="nestedblock--statement"></a>
### Nested Schema for `statement`

Optional:

- **actions** (Set of String)
- **condition** (Block Set) (see [below for nested schema](#nestedblock--statement--condition))
- **effect** (String)
- **principal** (String)
- **resources** (Set of String)
- **sid** (String)

<a id="nestedblock--statement--condition"></a>
### Nested Schema for `statement.condition`

Required:

- **test** (String)
- **values** (Set of String)
- **variable** (String)

