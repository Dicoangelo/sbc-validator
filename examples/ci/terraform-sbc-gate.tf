# Example: gate a Terraform-managed SBC change on sbc-validator.
#
# Pattern for IaC-mandated shops (the TP ICAP / SocGen workflow: "automation
# scripts for SBC configuration and provisioning"): Terraform renders or stages
# the candidate SBC config; this gate validates it BEFORE any provisioner or
# vendor API call applies it. The validator never touches the SBC itself —
# you stay the deployer; this is the check in front of your apply.
#
# Usage: terraform plan/apply fails when the verdict is REVIEW or worse.

variable "sbc_config_path" {
  description = "Path to the candidate SBC config export (rendered by your pipeline)"
  type        = string
  default     = "./rendered/sbc-teams-01.ini"
}

# The gate: runs at plan/apply time, fails the run on a bad verdict.
resource "terraform_data" "sbc_validate_gate" {
  # Re-run the gate whenever the candidate config changes.
  triggers_replace = {
    config_sha = filesha256(var.sbc_config_path)
  }

  provisioner "local-exec" {
    # --fail-on review: REVIEW or BLOCK exits non-zero and stops the apply.
    command = "sbc-validator validate '${var.sbc_config_path}' --fail-on review"
  }
}

# Your actual deployment step (vendor REST API, SCP, Ansible hand-off, etc.)
# depends on the gate, so it can never run against an unvalidated config.
# resource "null_resource" "push_to_sbc" {
#   depends_on = [terraform_data.sbc_validate_gate]
#   provisioner "local-exec" {
#     command = "./your-deploy-script.sh '${var.sbc_config_path}'"
#   }
# }
