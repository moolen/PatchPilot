package policy

// SchemaJSON returns a JSON schema for .patchpilot.yaml.
func SchemaJSON() []byte {
	return []byte(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "PatchPilot Policy",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "version": { "type": "integer", "const": 1 },
    "pre_execution": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "commands": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["run"],
            "properties": {
              "name": { "type": "string" },
              "run": { "type": "string", "minLength": 1 },
              "timeout": { "type": "string" },
              "fail_on_error": { "type": "boolean" }
            }
          }
        }
      }
    },
    "verification": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "mode": { "type": "string", "enum": ["append", "replace"] },
        "commands": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["run"],
            "properties": {
              "name": { "type": "string" },
              "run": { "type": "string", "minLength": 1 },
              "timeout": { "type": "string" }
            }
          }
        }
      }
    },
    "post_execution": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "commands": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["run"],
            "properties": {
              "name": { "type": "string" },
              "run": { "type": "string", "minLength": 1 },
              "when": { "type": "string", "enum": ["always", "success", "failure"] },
              "fail_on_error": { "type": "boolean" }
            }
          }
        }
      }
    },
    "exclude": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "cves": { "type": "array", "items": { "type": "string" } },
        "cve_rules": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["id"],
            "properties": {
              "id": { "type": "string", "minLength": 1 },
              "package": { "type": "string" },
              "ecosystem": { "type": "string" },
              "path": { "type": "string" },
              "reason": { "type": "string" },
              "owner": { "type": "string" },
              "expires_at": { "type": "string" }
            }
          }
        },
        "vulnerabilities": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["id"],
            "properties": {
              "id": { "type": "string", "minLength": 1 },
              "package": { "type": "string" },
              "ecosystem": { "type": "string" },
              "path": { "type": "string" },
              "reason": { "type": "string" },
              "owner": { "type": "string" },
              "expires_at": { "type": "string" }
            }
          }
        }
      }
    },
    "scan": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "skip_paths": { "type": "array", "items": { "type": "string" } },
        "cron": { "type": "string" },
        "timezone": { "type": "string" }
      }
    },
    "registry": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "cache": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "dir": { "type": "string" },
            "ttl": { "type": "string" }
          }
        },
        "auth": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "mode": { "type": "string", "enum": ["auto", "none", "bearer"] },
            "token_env": { "type": "string" }
          }
        }
      }
    },
    "docker": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "allowed_base_images": { "type": "array", "items": { "type": "string" } },
        "disallowed_base_images": { "type": "array", "items": { "type": "string" } },
        "patching": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "base_images": { "type": "string", "enum": ["auto", "disabled"] },
            "os_packages": { "type": "string", "enum": ["auto", "disabled"] }
          }
        }
      }
    },
    "go": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "patching": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "runtime": { "type": "string", "enum": ["disabled", "toolchain", "minimum"] }
          }
        }
      }
    },
    "agent": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "remediation_prompts": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "all": { "$ref": "#/$defs/remediation_prompt_list" },
            "baseline_scan_repair": {
              "type": "object",
              "additionalProperties": false,
              "properties": {
                "all": { "$ref": "#/$defs/remediation_prompt_list" },
                "generate_baseline_sbom": { "$ref": "#/$defs/remediation_prompt_list" },
                "scan_baseline": { "$ref": "#/$defs/remediation_prompt_list" }
              }
            },
            "fix_vulnerabilities": {
              "type": "object",
              "additionalProperties": false,
              "properties": {
                "all": { "$ref": "#/$defs/remediation_prompt_list" },
                "deterministic_fix_failed": { "$ref": "#/$defs/remediation_prompt_list" },
                "validation_failed": { "$ref": "#/$defs/remediation_prompt_list" },
                "vulnerabilities_remaining": { "$ref": "#/$defs/remediation_prompt_list" },
                "verification_regressed": { "$ref": "#/$defs/remediation_prompt_list" }
              }
            }
          }
        }
      }
    },
    "artifacts": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "targets_command": {
          "type": "object",
          "additionalProperties": false,
          "required": ["run"],
          "properties": {
            "run": { "type": "string", "minLength": 1 },
            "timeout": { "type": "string" },
            "mode": { "type": "string", "enum": ["replace", "append"] },
            "fail_on_error": { "type": "boolean" }
          }
        },
        "targets": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["dockerfile", "image", "build"],
            "properties": {
              "id": { "type": "string" },
              "dockerfile": { "type": "string", "minLength": 1 },
              "context": { "type": "string" },
              "image": {
                "type": "object",
                "additionalProperties": false,
                "required": ["tag"],
                "properties": {
                  "tag": { "type": "string", "minLength": 1 }
                }
              },
              "build": {
                "type": "object",
                "additionalProperties": false,
                "required": ["run"],
                "properties": {
                  "run": { "type": "string", "minLength": 1 },
                  "timeout": { "type": "string" }
                }
              },
              "scan": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                  "enabled": { "type": "boolean" }
                }
              }
            }
          }
        }
      }
    }
  },
  "$defs": {
    "remediation_prompt_list": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["mode", "template"],
        "properties": {
          "mode": { "type": "string", "enum": ["extend", "replace"] },
          "template": { "type": "string", "minLength": 1 }
        }
      }
    }
  }
}`)
}
