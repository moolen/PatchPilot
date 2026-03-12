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
    "oci": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "policies": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["source"],
            "properties": {
              "name": { "type": "string" },
              "source": { "type": "string", "minLength": 1 },
              "tags": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                  "allow": { "type": "array", "items": { "type": "string" } },
                  "deny": { "type": "array", "items": { "type": "string" } },
                  "semver": {
                    "type": "array",
                    "items": {
                      "type": "object",
                      "additionalProperties": false,
                      "properties": {
                        "range": { "type": "array", "items": { "type": "string", "minLength": 1 } },
                        "includePrerelease": { "type": "boolean" },
                        "prereleaseAllow": { "type": "array", "items": { "type": "string" } }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        "external_images": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["source", "dockerfiles"],
            "properties": {
              "source": { "type": "string", "minLength": 1 },
              "dockerfiles": {
                "type": "array",
                "minItems": 1,
                "items": { "type": "string", "minLength": 1 }
              },
              "tag": { "type": "string" }
            }
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
                "verification_regressed": { "$ref": "#/$defs/remediation_prompt_list" },
                "container_os_patching": { "$ref": "#/$defs/remediation_prompt_list" }
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
