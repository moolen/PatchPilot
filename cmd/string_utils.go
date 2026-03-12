package cmd

import "strings"

func sanitizeArtifactName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-", "..", "-")
	name = replacer.Replace(name)
	name = strings.Trim(name, "-")
	if name == "" {
		return "artifact"
	}
	return name
}
