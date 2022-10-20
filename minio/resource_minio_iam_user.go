package minio

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/minio/madmin-go"
)

func resourceMinioIAMUser() *schema.Resource {
	return &schema.Resource{
		CreateContext: minioCreateUser,
		ReadContext:   minioReadUser,
		UpdateContext: minioUpdateUser,
		DeleteContext: minioDeleteUser,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				Description:  "Access Key of the user",
				ValidateFunc: validateMinioIamUserName,
			},
			"secret": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Secret Key of the user",
				Sensitive:   true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"force_destroy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Delete user even if it has non-Terraform-managed IAM access keys",
			},
			"disable_user": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Disable user",
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tags": tagsSchema(),
		},
	}
}

// IAMUserConfig creates new user config
func IAMUserConfig(d *schema.ResourceData, meta interface{}) *S3MinioIAMUserConfig {
	m := meta.(*S3MinioClient)

	return &S3MinioIAMUserConfig{
		MinioAdmin:        m.S3Admin,
		MinioIAMName:      d.Get("name").(string),
		MinioSecret:       d.Get("secret").(string),
		MinioDisableUser:  d.Get("disable_user").(bool),
		MinioForceDestroy: d.Get("force_destroy").(bool),
	}
}

func minioCreateUser(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	iamUserConfig := IAMUserConfig(d, meta)

	var err error
	accessKey := iamUserConfig.MinioIAMName
	secretKey := iamUserConfig.MinioSecret

	err = iamUserConfig.MinioAdmin.AddUser(ctx, accessKey, secretKey)
	if err != nil {
		return NewResourceError("error creating user", accessKey, err)
	}

	d.SetId(aws.StringValue(&accessKey))

	if iamUserConfig.MinioDisableUser {
		err = iamUserConfig.MinioAdmin.SetUserStatus(ctx, accessKey, madmin.AccountDisabled)
		if err != nil {
			return NewResourceError("error disabling IAM User %s: %s", d.Id(), err)
		}
	}

	return minioReadUser(ctx, d, meta)
}

func minioUpdateUser(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	iamUserConfig := IAMUserConfig(d, meta)
	userStatus := UserStatus{}

	secretKey := iamUserConfig.MinioSecret

	userStatus = UserStatus{
		AccessKey: iamUserConfig.MinioIAMName,
		SecretKey: secretKey,
		Status:    madmin.AccountEnabled,
	}	

	if iamUserConfig.MinioDisableUser {
		userStatus.Status = madmin.AccountDisabled
	}

	//To analyze later and probably remove
	if iamUserConfig.MinioForceDestroy {
		return minioDeleteUser(ctx, d, meta)
	}

	userServerInfo, _ := iamUserConfig.MinioAdmin.GetUserInfo(ctx, iamUserConfig.MinioIAMName)
	if userServerInfo.Status != userStatus.Status {
		err := iamUserConfig.MinioAdmin.SetUserStatus(ctx, userStatus.AccessKey, userStatus.Status)
		if err != nil {
			return NewResourceError("error to disable IAM User %s: %s", d.Id(), err)
		}
	}

	if d.HasChange("secret"){
		err := iamUserConfig.MinioAdmin.SetUser(ctx, userStatus.AccessKey, userStatus.SecretKey, userStatus.Status)
		if err != nil {
			return NewResourceError("error updating IAM User Key %s: %s", d.Id(), err)
		}
	}

	return minioReadUser(ctx, d, meta)
}

func minioReadUser(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	iamUserConfig := IAMUserConfig(d, meta)

	output, err := iamUserConfig.MinioAdmin.GetUserInfo(ctx, d.Id())
	if err != nil {
		return NewResourceError("error reading IAM User %s: %s", d.Id(), err)
	}

	log.Printf("[WARN] (%v)", output)

	if _, ok := d.GetOk("name"); !ok {
		_ = d.Set("name", d.Id())
	}

	if err := d.Set("status", string(output.Status)); err != nil {
		return NewResourceError("reading IAM user failed", d.Id(), err)
	}

	return nil
}

func minioDeleteUser(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	iamUserConfig := IAMUserConfig(d, meta)

	// IAM Users must be removed from all groups before they can be deleted
	if err := deleteMinioIamUserGroupMemberships(ctx, iamUserConfig); err != nil {
		if iamUserConfig.MinioForceDestroy {
			// Ignore errors when deleting group memberships, continue deleting user
		} else {
			return NewResourceError("error removing IAM User (%s) group memberships: %s", d.Id(), err)
		}
	}

	err := deleteMinioIamUser(ctx, iamUserConfig)
	if err != nil {
		return NewResourceError("error deleting IAM User %s: %s", d.Id(), err)
	}

	// Actively set resource as deleted as the update path might force a deletion via MinioForceDestroy
	d.SetId("")

	return nil
}

func validateMinioIamUserName(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	if !regexp.MustCompile(`^[0-9A-Za-z=,.@\-_+]+$`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"only alphanumeric characters, hyphens, underscores, commas, periods, @ symbols, plus and equals signs allowed in %q: %q",
			k, value))
	}
	return
}

func deleteMinioIamUser(ctx context.Context, iamUserConfig *S3MinioIAMUserConfig) error {
	log.Println("[DEBUG] Deleting IAM User request:", iamUserConfig.MinioIAMName)
	err := iamUserConfig.MinioAdmin.RemoveUser(ctx, iamUserConfig.MinioIAMName)
	if err != nil {
		return err
	}
	return nil
}

func deleteMinioIamUserGroupMemberships(ctx context.Context, iamUserConfig *S3MinioIAMUserConfig) error {

	userInfo, _ := iamUserConfig.MinioAdmin.GetUserInfo(ctx, iamUserConfig.MinioIAMName)

	groupsMemberOf := userInfo.MemberOf

	for _, groupMemberOf := range groupsMemberOf {

		log.Printf("[DEBUG] Removing IAM User %s from IAM Group %s", iamUserConfig.MinioIAMName, groupMemberOf)
		groupAddRemove := madmin.GroupAddRemove{
			Group:    groupMemberOf,
			Members:  []string{iamUserConfig.MinioIAMName},
			IsRemove: true,
		}

		err := iamUserConfig.MinioAdmin.UpdateGroupMembers(ctx, groupAddRemove)
		if err != nil {
			return err
		}

	}

	return nil

}