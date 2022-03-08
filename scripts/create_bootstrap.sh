#!/bin/bash

PRINT() {
cat << _TEXTBLOCK_
${INPUT_TEXT}
_TEXTBLOCK_
}

CHECK_TF_BIN="$(which terraform)"

if [ "${CHECK_TF_BIN}" == "" ]; then
  yum -y install yum-utils
  yum-config-manager --add-repo https://rpm.releases.hashicorp.com/$release/hashicorp.repo
  yum -y install terraform
  CHECK_TF_BIN="$(which terraform)"
fi

# SCRIPT_DIR=$(dirname "$0")
PROJECTS_DIR="/opt/scripts/PROJECTS"
PLAYBOOKS_DIR="${PROJECTS_DIR}/playbooks"

if ! [ -d  ${PLAYBOOKS_DIR} ]; then
  mkdir -p "${PLAYBOOKS_DIR}"
fi

cd "${PLAYBOOKS_DIR}" || exit

IS_ALLOW() {
  local LIST="${CHECK_LIST}"
  local ITEM="${CHECK_ITEM}"

  if [[ ${LIST} =~ (^|[[:space:]])"${ITEM}"($|[[:space:]]) ]] ; then
    return 0
  else
    echo "${ITEM} is not allowed."
    exit
  fi
}

IS_VALID() {
  if ! [[ "${CHECK_CHARS}" =~ ^[-[:alnum:]]+$ ]]; then
    echo ""
    echo "${CHECK_CHARS} : contains invalid characters. Only apha-numerics and '-' are allow."
    echo ""
    exit
  fi
}

DIE() {
  printf '%s\n' "${1}" >&2
  exit 1
}

USAGE() {
  echo "------------------------------------------------------------------------------------------------------------------------"
  echo
  echo "$0 [-h|--help] [-p|--project] {project_name} [-e|--env] { environment } [-c|--command] { command }"
  echo
  echo
}

if [ "${1}" == "" ]; then
  USAGE
  exit
fi

while :; do
  case ${1} in
    -h|--help)
      USAGE
      exit
      ;;
    -p|--project)
      if [ "${2}" ]; then
        CHECK_CHARS=${2}; IS_VALID
        PROJECT=${2}
        shift
      else
        DIE 'ERROR: "---'
      fi
      ;;
    -s|--sub-project)
      if [ "${2}" ]; then
        CHECK_CHARS=${2}; IS_VALID
        SUB_PROJECT=${2}
        shift
      else
        DIE 'ERROR: "---'
      fi
      ;;
    -e|--env)
      if [ "${2}" ]; then
        CHECK_CHARS=${2}; IS_VALID
        ENV=${2}
        BOOTSTRAP_PREFIX="vdevops-${PROJECT}"
        shift
      else
        DIE 'ERROR: "---'
      fi
      ;;
    -c|--command)
      if [ "${2}" ]; then
        COMMAND="${2}"
        shift
      else
        DIE 'ERROR: "--command" requires a non-empty option argument.'
      fi
      ;;
    *)
      break
      ;;
  esac
  shift
done

if ! [ "${SUB_PROJECT}" == "" ]; then
  ENV_CONFIG="${SUB_PROJECT}-${ENV}"
else
  ENV_CONFIG="${ENV}"
fi

COMMON_TFVARS="$(cat << _TEXTBLOCK_
REGION                  = "ap-southeast-2"
MANAGED_BY              = "VDEVOPS"
BOOTSTRAP_PREFIX        = "vdevops-${PROJECT}"

S3_BUCKET_LOGGING       = "enabled"
S3_BUCKET_ACL           = "private"
S3_BUCKET_VERSIONING    = "enabled"
S3_BUCKET_ENCRYPTION    = "enabled"
S3_BUCKET_ALLOW_REMOVAL = false

S3_LOGS_LOGGING         = "disabled"
S3_LOGS_ACL             = "log-delivery-write"
S3_LOGS_VERSIONING      = "enabled"
S3_LOGS_ENCRYPTION      = "enabled"
S3_LOGS_ALLOW_REMOVAL   = false

DYNAMODB_BILLING_MODE   = "PAY_PER_REQUEST"
DYNAMODB_HASH_KEY       = "LockID"
DYNAMODB_ENCRYPTION     = "enabled"
_TEXTBLOCK_
)"

ROOT_VARS_TF="$(cat << '_TEXTBLOCK_'
variable "ENV" {}
variable "REGION" {}
variable "MANAGED_BY" {}
variable "BOOTSTRAP_PREFIX" {}

variable "S3_BUCKET_LOGGING" {}
variable "S3_BUCKET_ACL" {}
variable "S3_BUCKET_VERSIONING" {}
variable "S3_BUCKET_ENCRYPTION" {}
variable "S3_BUCKET_ALLOW_REMOVAL" {}

variable "S3_LOGS_LOGGING" {}
variable "S3_LOGS_ACL" {}
variable "S3_LOGS_VERSIONING" {}
variable "S3_LOGS_ENCRYPTION" {}
variable "S3_LOGS_ALLOW_REMOVAL" {}

variable "DYNAMODB_BILLING_MODE" {}
variable "DYNAMODB_HASH_KEY" {}
variable "DYNAMODB_ENCRYPTION" {}
_TEXTBLOCK_
)"

BOOTSTRAP_TF="$(cat << '_TEXTBLOCK_'
module "tf_bootstrap" {
  source        = "./modules/bootstrap"
  for_each      = local.BOOTSTRAP_INFO
  states_bucket = each.value.S3_BUCKET
  states_logs   = each.value.S3_LOGS
  states_lock   = each.value.DYNAMODB
}
_TEXTBLOCK_
)"

LOCALS_TF="$(cat << '_TEXTBLOCK_'
locals {
  COMMON_TAGS = {
    ManagedBy   = var.MANAGED_BY
    Environment = var.ENV
  }

  BOOTSTRAP_PREFIX = "${var.BOOTSTRAP_PREFIX}-${var.ENV}"

  BOOTSTRAP_INFO = {
    "BOOTSTRAP" = {
      "S3_BUCKET" = {
        "STATES_BUCKET" = { name          = "${local.BOOTSTRAP_PREFIX}-states",
                            az            = var.REGION,
                            logging       = var.S3_BUCKET_LOGGING,
                            acl           = var.S3_BUCKET_ACL,
                            versioning    = var.S3_BUCKET_VERSIONING,
                            encryption    = var.S3_BUCKET_ENCRYPTION,
                            allow_removal = var.S3_BUCKET_ALLOW_REMOVAL,
                            tags          = merge(local.COMMON_TAGS, { Name = "${local.BOOTSTRAP_PREFIX}-states" })
        },
      },
      "S3_LOGS" = {
        "STATES_LOGS" = { name          = "${local.BOOTSTRAP_PREFIX}-states-logs",
                          az            = var.REGION,
                          logging       = var.S3_LOGS_LOGGING,
                          acl           = var.S3_LOGS_ACL,
                          versioning    = var.S3_LOGS_VERSIONING,
                          encryption    = var.S3_LOGS_ENCRYPTION,
                          allow_removal = var.S3_LOGS_ALLOW_REMOVAL,
                          tags          = merge(local.COMMON_TAGS, { Name = "${local.BOOTSTRAP_PREFIX}-states-logs" })
        },
      },
      "DYNAMODB" = {
        "STATES_LOCK" = { name         = "${local.BOOTSTRAP_PREFIX}-states-lock",
                          billing_mode = var.DYNAMODB_BILLING_MODE,
                          hash_key     = var.DYNAMODB_HASH_KEY,
                          encryption   = var.DYNAMODB_ENCRYPTION,
                          tags         = merge(local.COMMON_TAGS, { Name = "${local.BOOTSTRAP_PREFIX}-states-lock" })
        },
      },
    }
  }
}
_TEXTBLOCK_
)"

OUTPUTS_TF="$(cat << '_TEXTBLOCK_'
data "aws_caller_identity" "current" {}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "bootstrap_info" {
  value = module.tf_bootstrap
}
_TEXTBLOCK_
)"


PROFILE_NAME="${PROJECT}_${ENV}"

PROVIDERS_TF="$(cat << _TEXTBLOCK_
terraform {
  backend "local" {}
}

provider "aws" {
  region  = var.REGION
  profile = "${PROFILE_NAME}"
}
_TEXTBLOCK_
)"

ASSUME_ROLE_SCRIPT="$(cat << _TEXTBLOCK_
#!/bin/bash

if ! [ -e ~/.saml2aws ]; then 
  sh /opt/scripts/saml2aws/init-saml2aws.sh
fi

sh /opt/scripts/saml2aws/saml2aws.sh

export AWS_PROFILE="vdevops-main"
ROLE_ARN='arn:aws:iam::422145674183:role/PROJECTS_FullAccessRole'
ROLE_SESSION_NAME='${PROFILE_NAME}_session'
PROFILE_NAME='${PROFILE_NAME}'

TEMP_ROLE=\$(aws sts assume-role --role-arn \${ROLE_ARN} --role-session-name \${ROLE_SESSION_NAME})

AWS_ACCESS_KEY_ID="\$(echo \${TEMP_ROLE} | jq -r .Credentials.AccessKeyId)"
AWS_SECRET_ACCESS_KEY="\$(echo \${TEMP_ROLE} | jq -r .Credentials.SecretAccessKey)"
AWS_SESSION_TOKEN="\$(echo \${TEMP_ROLE} | jq -r .Credentials.SessionToken)"

aws configure set profile.\${PROFILE_NAME}.aws_access_key_id "\${AWS_ACCESS_KEY_ID}"
aws configure set profile.\${PROFILE_NAME}.aws_secret_access_key "\${AWS_SECRET_ACCESS_KEY}"
aws configure set profile.\${PROFILE_NAME}.aws_session_token "\${AWS_SESSION_TOKEN}"
_TEXTBLOCK_
)"

MODULE_DATA_TF="$(cat << '_TEXTBLOCK_'
data "aws_canonical_user_id" "current" {}

data "aws_iam_policy_document" "s3_policy" {
  for_each = var.states_bucket
  statement {
    effect = "Deny"

    principals {
      identifiers = ["*"]
      type        = "AWS"
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${each.value.name}/*",
    ]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"

      values = [
        "AES256",
      ]
    }
  }

  statement {
    effect = "Deny"

    principals {
      identifiers = ["*"]
      type        = "AWS"
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${each.value.name}/*",
    ]

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"

      values = [
        "true",
      ]
    }
  }
}
_TEXTBLOCK_
)"

MODULE_DYNAMODB_TF="$(cat << '_TEXTBLOCK_'
resource "aws_dynamodb_table" "terraform_state_lock" {
  for_each     = var.states_lock
  name         = each.value.name
  billing_mode = each.value.billing_mode
  hash_key     = each.value.hash_key

  attribute {
    name = "LockID"
    type = "S"
  }

  dynamic "server_side_encryption" {
    for_each = range(each.value.encryption == "enabled" ? 1 : 0)
    content {
      enabled = true
    }
  }

  dynamic "server_side_encryption" {
    for_each = range(each.value.encryption == "disabled" ? 1 : 0)
    content {
      enabled = false
    }
  }

  tags = each.value.tags
}
_TEXTBLOCK_
)"

MODULE_S3_TF="$(cat << '_TEXTBLOCK_'
#-------------------------------------------------------------------------------------
# TERRAFORM STATES BUCKET LOGS
#-------------------------------------------------------------------------------------

resource "aws_s3_bucket" "terraform_state_logs" {
  for_each = var.states_logs
  bucket   = each.value.name

  tags = each.value.tags
}

resource "aws_s3_bucket_versioning" "terraform_state_logs_versioning" {
  for_each = var.states_logs
  bucket   = aws_s3_bucket.terraform_state_logs[each.key].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_acl" "terraform_state_logs_acl" {
  for_each = var.states_logs
  bucket   = aws_s3_bucket.terraform_state_logs[each.key].id
  acl      = each.value.acl
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state_logs_encryption" {
  for_each = var.states_logs
  bucket   = aws_s3_bucket.terraform_state_logs[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      # kms_master_key_id = data.aws_kms_key.s3.arn
      # sse_algorithm     = "aws:kms"
      sse_algorithm     = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "terraform_state_logs_lifecycle" {
  for_each = var.states_logs
  bucket   = aws_s3_bucket.terraform_state_logs[each.key].id

  rule {
    id     = "logs"
    status = "Enabled"

    filter {
      prefix = "logs/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    # transition {
    #   days          = 180
    #   storage_class = "DEEP_ARCHIVE"
    # }

    expiration {
      days = 365
    }
  }
}


#-------------------------------------------------------------------------------------
# TERRAFORM STATES BUCKET
#-------------------------------------------------------------------------------------

resource "aws_s3_bucket" "terraform_state" {
  for_each = var.states_bucket
  bucket   = each.value.name

  tags = each.value.tags
}

resource "aws_s3_bucket_logging" "terraform_state_logging" {
  for_each = var.states_bucket
  bucket   = each.value.name

  target_bucket = aws_s3_bucket.terraform_state_logs["STATES_LOGS"].id
  target_prefix = "logs/"
}

resource "aws_s3_bucket_policy" "terraform_state_policy" {
  for_each = var.states_bucket
  bucket   = each.value.name
  policy   = data.aws_iam_policy_document.s3_policy[each.key].json

  depends_on = [
    aws_s3_bucket.terraform_state["STATES_BUCKET"]
  ]
}

resource "aws_s3_bucket_versioning" "terraform_state_versioning" {
  for_each = var.states_bucket
  bucket   = aws_s3_bucket.terraform_state[each.key].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_acl" "terraform_state_acl" {
  for_each = var.states_bucket
  bucket   = aws_s3_bucket.terraform_state[each.key].id
  acl      = each.value.acl
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state_encryption" {
  for_each = var.states_bucket
  bucket   = aws_s3_bucket.terraform_state[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      # kms_master_key_id = data.aws_kms_key.s3.arn
      # sse_algorithm     = "aws:kms"
      sse_algorithm     = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "terraform_state_lifecycle" {
  for_each = var.states_bucket
  bucket   = aws_s3_bucket.terraform_state[each.key].id

  rule {
    id     = "logs"
    status = "Enabled"

    filter {
      prefix = "logs/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    # transition {
    #   days          = 180
    #   storage_class = "DEEP_ARCHIVE"
    # }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state_logs" {
  for_each                = var.states_logs
  bucket                  = aws_s3_bucket.terraform_state_logs[each.key].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  for_each                = var.states_bucket
  bucket                  = aws_s3_bucket.terraform_state[each.key].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
_TEXTBLOCK_
)"

MODULE_OUTPUTS_TF="$(cat << '_TEXTBLOCK_'
output "dynamodb_into" {
  value = aws_dynamodb_table.terraform_state_lock
}

output "s3_bucket_info" {
  value = aws_s3_bucket.terraform_state
}

output "s3_logs_info" {
  value = aws_s3_bucket.terraform_state_logs
}
_TEXTBLOCK_
)"

MODULE_VARS_TF="$(cat << '_TEXTBLOCK_'
variable "states_lock" {}
variable "states_bucket" {}
variable "states_logs" {}
_TEXTBLOCK_
)"

BOOTSTRAP_CONFIG() {
  cd "${PLAYBOOKS_DIR}/${PROJECT}/bootstrap" || exit

  for DIR in states backend vars; do 
    if ! [ -d config/${DIR} ]; then
      mkdir -p config/${DIR}
    fi
  done

  if ! [ -d config/states/"${ENV_CONFIG}" ]; then
    mkdir -p config/states/"${ENV_CONFIG}"
  fi

  if ! [ -e "config/backend/backend_${ENV_CONFIG}.hcl" ]; then
    INPUT_TEXT="path = \"./config/states/${ENV_CONFIG}/terraform.tfstate\""; PRINT > "./config/backend/backend_${ENV_CONFIG}.hcl"
  fi

  if ! [ -e "./config/vars/vars_${ENV_CONFIG}.tfvars" ]; then
    INPUT_TEXT="ENV = \"${ENV_CONFIG}\""; PRINT > "./config/vars/vars_${ENV_CONFIG}.tfvars"
  fi

  if ! [ -e ./config/vars/vars_common.tfvars ]; then
    INPUT_TEXT="${COMMON_TFVARS}"; PRINT > ./config/vars/vars_common.tfvars
  fi
}

BOOTSTRAP_MODULE() {
  cd "${PLAYBOOKS_DIR}/${PROJECT}/bootstrap" || exit

  if ! [ -d ./modules/bootstrap ]; then
    mkdir -p ./modules/bootstrap
  fi

  if ! [ -e ./bootstrap.tf ]; then
    INPUT_TEXT="${BOOTSTRAP_TF}"; PRINT > ./bootstrap.tf
  fi

  if ! [ -e ./locals.tf ]; then
    INPUT_TEXT="${LOCALS_TF}"; PRINT > ./locals.tf
  fi

  if ! [ -e ./outputs.tf ]; then
    INPUT_TEXT="${OUTPUTS_TF}"; PRINT > ./outputs.tf
  fi

  if ! [ -e ./provider.tf ]; then
    INPUT_TEXT="${PROVIDERS_TF}"; PRINT > ./provider.tf
  fi

  if ! [ -e ./assume_role.sh ]; then
    INPUT_TEXT="${ASSUME_ROLE_SCRIPT}"; PRINT > ./assume_role.sh
  fi

  if ! [ -e ./vars.tf ]; then
    INPUT_TEXT="${ROOT_VARS_TF}"; PRINT > ./vars.tf
  fi

  if ! [ -e ./modules/bootstrap/data.tf ]; then
    INPUT_TEXT="${MODULE_DATA_TF}"; PRINT > ./modules/bootstrap/data.tf
  fi

  if ! [ -e ./modules/bootstrap/dynamodb.tf ]; then
    INPUT_TEXT="${MODULE_DYNAMODB_TF}"; PRINT > ./modules/bootstrap/dynamodb.tf
  fi

  if ! [ -e ./modules/bootstrap/s3.tf ]; then
    INPUT_TEXT="${MODULE_S3_TF}"; PRINT > ./modules/bootstrap/s3.tf
  fi

  if ! [ -e ./modules/bootstrap/outputs.tf ]; then
    INPUT_TEXT="${MODULE_OUTPUTS_TF}"; PRINT > ./modules/bootstrap/outputs.tf
  fi

  if ! [ -e ./modules/bootstrap/vars.tf ]; then
    INPUT_TEXT="${MODULE_VARS_TF}"; PRINT > ./modules/bootstrap/vars.tf
  fi
}

RUN_BOOTSTRAP_SCRIPT="$(cat << _TEXTBLOCK_
#!/bin/bash -exi

REGION="ap-southeast-2"
TF_BIN="${CHECK_TF_BIN}"

alias TF_CMD="AWS_REGION=\${REGION} \${TF_BIN}"

DEPLOY() {
  if [ -e ./config/backend/backend_${ENV_CONFIG}.hcl ]; then
    if ! [ -e ./config/states/${ENV}/terraform.tfstate ]; then
      TF_CMD init -reconfigure -backend-config=./config/backend/backend_${ENV_CONFIG}.hcl
    else
      TF_CMD init -backend-config=./config/backend/backend_${ENV_CONFIG}.hcl
    fi
  
    if [ -e ./config/vars/vars_${ENV_CONFIG}.tfvars ] && [ -e ./config/vars/vars_common.tfvars ]; then
      TF_CMD plan -state=./config/states/${ENV}/terraform.tfstate -var-file=./config/vars/vars_${ENV_CONFIG}.tfvars -var-file=./config/vars/vars_common.tfvars
      TF_CMD apply -state=./config/states/${ENV}/terraform.tfstate -var-file=./config/vars/vars_${ENV_CONFIG}.tfvars -var-file=./config/vars/vars_common.tfvars
    else
      echo "TFVARS files is missing."
      exit
    fi
  else
    echo "./config/backend/backend_${ENV_CONFIG}.hcl not found... exiting."
    exit
  fi
}

DESTROY() {
  TF_CMD destroy -state=./config/states/${ENV}/terraform.tfstate -var-file=./config/vars/vars_${ENV_CONFIG}.tfvars -var-file=./config/vars/vars_common.tfvars
}

if [ "\${1}" == "deploy" ]; then
  DEPLOY
elif [ "\${1}" == "destroy" ]; then
  DESTROY
fi
_TEXTBLOCK_
)"


RUN_TERRAFORM_SCRIPT="$(cat << _TEXTBLOCK_
#!/bin/bash -ex

REGION="ap-southeast-2"
TF_BIN="/opt/repos/hashicorp/terraform/terraform"

alias TF_CMD="AWS_REGION=\${REGION} \${TF_BIN}"

DEPLOY() {
  if [ -e ./config/backend/backend_${ENV_CONFIG}.hcl ]; then
    if ! [ -e ./config/states/${ENV}/terraform.tfstate ]; then
      TF_CMD init -reconfigure -backend-config=./config/backend/backend_${ENV_CONFIG}.hcl
    else
      TF_CMD init -backend-config=./config/backend/backend_${ENV_CONFIG}.hcl
    fi
  
    if [ -e ./config/vars/vars_${ENV_CONFIG}.tfvars ] && [ -e ./config/vars/vars_common.tfvars ]; then
      TF_CMD plan -state=./config/states/${ENV}/terraform.tfstate -var-file=./config/vars/vars_${ENV_CONFIG}.tfvars -var-file=./config/vars/vars_common.tfvars
      TF_CMD apply -state=./config/states/${ENV}/terraform.tfstate -var-file=./config/vars/vars_${ENV_CONFIG}.tfvars -var-file=./config/vars/vars_common.tfvars
    else
      echo "TFVARS files is missing."
      exit
    fi
  else
    echo "./config/backend/backend_${ENV_CONFIG}.hcl not found... exiting."
    exit
  fi
}

DESTROY() {
  TF_CMD destroy -state=./config/states/${ENV}/terraform.tfstate -var-file=./config/vars/vars_${ENV_CONFIG}.tfvars -var-file=./config/vars/vars_common.tfvars
}

if [ "\${1}" == "deploy" ]; then
  DEPLOY
elif [ "\${1}" == "destroy" ]; then
  DESTROY
fi
_TEXTBLOCK_
)"

RUN_BOOTSTRAP_SH() {
  cd "${PLAYBOOKS_DIR}/${PROJECT}/bootstrap" || exit

  if ! [ -e "./run_bootstrap_${ENV_CONFIG}.sh" ]; then
    INPUT_TEXT="${RUN_BOOTSTRAP_SCRIPT}"; PRINT > "./run_bootstrap_${ENV_CONFIG}.sh"
    chmod +x "./run_bootstrap_${ENV_CONFIG}.sh"
  fi
}

RUN_TERRAFORM_SH() {
  cd "${PLAYBOOKS_DIR}/${PROJECT}/${SUB_PROJECT}" || exit

  if ! [ -e "./run_terraform_${ENV_CONFIG}.sh" ]; then
    INPUT_TEXT="${RUN_TERRAFORM_SCRIPT}"; PRINT > "./run_terraform_${ENV_CONFIG}.sh"
    chmod +x "./run_terraform_${ENV_CONFIG}.sh"
  fi
}

HELLO_WORLD_BACKEND_HCL="$(cat << _TEXTBLOCK_
region         = "ap-southeast-2"
bucket         = "${BOOTSTRAP_PREFIX}-${ENV_CONFIG}-states"
dynamodb_table = "${BOOTSTRAP_PREFIX}-${ENV_CONFIG}-states-lock"
encrypt        = "true"
key            = "${BOOTSTRAP_PREFIX}-${ENV_CONFIG}/terraform.tfstate"
_TEXTBLOCK_
)"

HELLO_WORLD_OUTPUT="$(cat << _TEXTBLOCK_
output "init_statesfile" {
  value = "Initilizing states for: \${var.ENV}"
}
_TEXTBLOCK_
)"

HELLO_WORLD_PROVIDERS="$(cat << _TEXTBLOCK_
terraform {
  backend "s3" {}
}

provider "aws" {
  region = "ap-southeast-2"
}
_TEXTBLOCK_
)"

HELLO_WORLD(){
  cd "${PLAYBOOKS_DIR}/${PROJECT}" || exit

  if ! [ -d "${SUB_PROJECT}" ]; then
    mkdir -p "${SUB_PROJECT}/config/{backend,vars}"
    mkdir -p "${SUB_PROJECT}/modules"
    INPUT_TEXT="ENV = \"${ENV_CONFIG}\""; PRINT > "${SUB_PROJECT}/config/vars/vars_${ENV_CONFIG}.tfvars"
    touch "${SUB_PROJECT}/config/vars/vars_common.tfvars"
    INPUT_TEXT="variable \"ENV\" {}"; PRINT > "${SUB_PROJECT}/vars.tf"

    INPUT_TEXT="${HELLO_WORLD_BACKEND_HCL}"; PRINT > ${SUB_PROJECT}/config/backend/backend_${ENV_CONFIG}.hcl
    INPUT_TEXT="${HELLO_WORLD_PROVIDERS}"; PRINT > ${SUB_PROJECT}/providers.tf

    INPUT_TEXT="${HELLO_WORLD_OUTPUT}"; PRINT > ${SUB_PROJECT}/hello_world.tf
    RUN_BOOTSTRAP_SH
    RUN_TERRAFORM_SH
  fi
}

CHECK_GO_BIN="$(which go)"

if [ "${CHECK_GO_BIN}" == "" ]; then
  yum -y install go-toolset
  CHECK_GO_BIN="$(which go)"
fi

GOOGLE_SDK_REPO="$(cat << _TXTBLOCK_
[google-cloud-sdk]
name=Google Cloud SDK
baseurl=https://packages.cloud.google.com/yum/repos/cloud-sdk-el8-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=0
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg
       https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
_TXTBLOCK_
)"

GOOGLE_SDK_REPO_FILE="/etc/yum.repos.d/google-cloud-sdk.repo"

if ! [ -e ${GOOGLE_SDK_REPO_FILE} ]; then
  INPUT_TEXT="${GOOGLE_SDK_REPO}"; PRINT > ${GOOGLE_SDK_REPO_FILE}
fi

CHECK_GCLOUD_BIN="$(which gcloud)"

if [ "${CHECK_GCLOUD_BIN}" == "" ]; then
  yum -y install google-cloud-sdk
  CHECK_GCLOUD_BIN="$(which go)"
fi

CHECK_KUBECTL_BIN="$(which kubectl)"

if [ "${CHECK_KUBECTL_BIN}" == "" ]; then
  yum -y install kubectl
  CHECK_KUBECTL_BIN="$(which kubectl)"
fi

CHECK_GIT_BIN="$(which git)"

if [ "${CHECK_GIT_BIN}" == "" ]; then
  yum -y install git
  CHECK_KUBECTL_BIN="$(which git)"
fi

if ! [ "${PROJECT}" == "" ] && ! [ "${ENV}" == "" ] && [ "${COMMAND}" == "create" ]; then
  if ! [ -d "${PROJECT}/bootstrap" ]; then
    mkdir -p "${PROJECT}/bootstrap"
    BOOTSTRAP_CONFIG
    BOOTSTRAP_MODULE
    RUN_BOOTSTRAP_SH
  else
    BOOTSTRAP_CONFIG
    BOOTSTRAP_MODULE
    RUN_BOOTSTRAP_SH
  fi
  tree "${PLAYBOOKS_DIR}/${PROJECT}"
else
  USAGE
fi
