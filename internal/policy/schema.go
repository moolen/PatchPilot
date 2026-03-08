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
        "skip_paths": { "type": "array", "items": { "type": "string" } }
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
    }
  }
}`)
}
