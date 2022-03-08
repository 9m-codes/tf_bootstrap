#!/bin/bash

# SCRIPT_DIR=$(dirname "$0")
PROJECTS_DIR="/opt/workspace/PROJECTS"
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

PROVIDERS_TF="$(cat << '_TEXTBLOCK_'
terraform {
  backend "local" {}
}

provider "aws" {
  region = var.REGION
}
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
resource "aws_s3_bucket" "terraform_state" {
  for_each      = var.states_bucket
  bucket        = each.value.name
  acl           = each.value.acl
  force_destroy = each.value.allow_removal
  policy        = data.aws_iam_policy_document.s3_policy["STATES_BUCKET"].json

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  logging {
    target_bucket = aws_s3_bucket.terraform_state_logs["STATES_LOGS"].id
    target_prefix = "log/"
  }

  dynamic "versioning" {
    for_each = range(each.value.encryption == "enabled" ? 1 : 0)
    content {
      enabled = true
    }
  }

  dynamic "versioning" {
    for_each = range(each.value.encryption == "disabled" ? 1 : 0)
    content {
      enabled = false
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = each.value.tags
}

resource "aws_s3_bucket" "terraform_state_logs" {
  for_each      = var.states_logs
  bucket        = each.value.name
  acl           = each.value.acl
  force_destroy = each.value.allow_removal

  lifecycle_rule {
    enabled = true
    id      = "log"
    prefix  = "log/"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  dynamic "versioning" {
    for_each = range(each.value.encryption == "enabled" ? 1 : 0)
    content {
      enabled = true
    }
  }

  dynamic "versioning" {
    for_each = range(each.value.encryption == "disabled" ? 1 : 0)
    content {
      enabled = false
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = each.value.tags
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket                  = aws_s3_bucket.terraform_state["STATES_BUCKET"].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "terraform_state_logs" {
  bucket                  = aws_s3_bucket.terraform_state_logs["STATES_LOGS"].id
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
    if ! [ -d ./config/${DIR} ]; then
      mkdir -p ./config/${DIR}
    fi
  done

  if ! [ -d ./config/states/"${ENV_CONFIG}" ]; then
    mkdir -p ./config/states/"${ENV_CONFIG}"
  fi

  if ! [ -e "./config/backend/backend_${ENV_CONFIG}.hcl" ]; then
    echo "path = \"./config/states/${ENV_CONFIG}/terraform.tfstate\"" | tee ./config/backend/backend_"${ENV_CONFIG}".hcl > /dev/null
  fi

  if ! [ -e "./config/vars/vars_${ENV_CONFIG}.tfvars" ]; then
    echo "ENV = \"${ENV_CONFIG}\"" | tee "./config/vars/vars_${ENV_CONFIG}.tfvars" > /dev/null
  fi

  if ! [ -e ./config/vars/vars_common.tfvars ]; then
    echo "${COMMON_TFVARS}" | tee ./config/vars/vars_common.tfvars > /dev/null
  fi
}

BOOTSTRAP_MODULE() {
  cd "${PLAYBOOKS_DIR}/${PROJECT}/bootstrap" || exit

  if ! [ -d ./modules/bootstrap ]; then
    mkdir -p ./modules/bootstrap
  fi

  if ! [ -e ./bootstrap.tf ]; then
    echo -e "${BOOTSTRAP_TF}" | tee ./bootstrap.tf > /dev/null
  fi

  if ! [ -e ./locals.tf ]; then
    echo -e "${LOCALS_TF}" | tee ./locals.tf > /dev/null
  fi

  if ! [ -e ./outputs.tf ]; then
    echo -e "${OUTPUTS_TF}" | tee ./outputs.tf > /dev/null
  fi

  if ! [ -e ./provider.tf ]; then
    echo -e "${PROVIDERS_TF}" | tee ./provider.tf > /dev/null
  fi

  if ! [ -e ./vars.tf ]; then
    echo -e "${ROOT_VARS_TF}" | tee ./vars.tf > /dev/null
  fi

  if ! [ -e ./modules/bootstrap/data.tf ]; then
    echo -e "${MODULE_DATA_TF}" | tee ./modules/bootstrap/data.tf > /dev/null
  fi

  if ! [ -e ./modules/bootstrap/dynamodb.tf ]; then
    echo -e "${MODULE_DYNAMODB_TF}" | tee ./modules/bootstrap/dynamodb.tf > /dev/null
  fi

  if ! [ -e ./modules/bootstrap/s3.tf ]; then
    echo -e "${MODULE_S3_TF}" | tee ./modules/bootstrap/s3.tf > /dev/null
  fi

  if ! [ -e ./modules/bootstrap/outputs.tf ]; then
    echo -e "${MODULE_OUTPUTS_TF}" | tee ./modules/bootstrap/outputs.tf > /dev/null
  fi

  if ! [ -e ./modules/bootstrap/vars.tf ]; then
    echo -e "${MODULE_VARS_TF}" | tee ./modules/bootstrap/vars.tf > /dev/null
  fi
}

RUN_BOOTSTRAP_SCRIPT="$(cat << _TEXTBLOCK_
#!/bin/bash -exi

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


RUN_TERRAFORM_SCRIPT="$(cat << _TEXTBLOCK_
#!/bin/bash -exi

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
    echo -e "${RUN_BOOTSTRAP_SCRIPT}" | tee "./run_bootstrap_${ENV_CONFIG}.sh" > /dev/null
    chmod +x "./run_bootstrap_${ENV_CONFIG}.sh"
  fi
}

RUN_TERRAFORM_SH() {
  cd "${PLAYBOOKS_DIR}/${PROJECT}/${SUB_PROJECT}" || exit

  if ! [ -e "./run_terraform_${ENV_CONFIG}.sh" ]; then
    echo -e "${RUN_TERRAFORM_SCRIPT}" | tee "./run_terraform_${ENV_CONFIG}.sh" > /dev/null
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

  if ! [ -d ./${SUB_PROJECT} ]; then
    mkdir -p ./${SUB_PROJECT}/config/{backend,vars}
    mkdir -p ./${SUB_PROJECT}/modules
    echo "ENV = \"${ENV_CONFIG}\"" | tee ./${SUB_PROJECT}/config/vars/vars_${ENV_CONFIG}.tfvars > /dev/null
    touch ./${SUB_PROJECT}/config/vars/vars_common.tfvars
    echo "variable \"ENV\" {}" | tee ./${SUB_PROJECT}/vars.tf > /dev/null

    echo -e "${HELLO_WORLD_BACKEND_HCL}" | tee ./${SUB_PROJECT}/config/backend/backend_${ENV_CONFIG}.hcl > /dev/null
    echo -e "${HELLO_WORLD_PROVIDERS}" | tee ./${SUB_PROJECT}/providers.tf > /dev/null

    echo -e "${HELLO_WORLD_OUTPUT}" | tee ./${SUB_PROJECT}/hello_world.tf > /dev/null
    RUN_BOOTSTRAP_SH
    RUN_TERRAFORM_SH
  fi
}

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
