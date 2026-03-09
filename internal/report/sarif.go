package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/moolen/patchpilot/internal/vuln"
)

const sarifFile = "findings.sarif"

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results,omitempty"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string               `json:"id"`
	ShortDescription sarifMessageFragment `json:"shortDescription"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifMessageFragment   `json:"message"`
	Locations  []sarifLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifMessageFragment struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

func WriteSARIF(repo string, findings []vuln.Finding) error {
	if err := ensureStateDir(repo); err != nil {
		return err
	}

	rulesByID := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		ruleID := strings.TrimSpace(finding.VulnerabilityID)
		if ruleID == "" {
			ruleID = "unknown-vulnerability"
		}
		if _, ok := rulesByID[ruleID]; !ok {
			rulesByID[ruleID] = sarifRule{
				ID:               ruleID,
				ShortDescription: sarifMessageFragment{Text: ruleID},
			}
		}

		message := fmt.Sprintf("%s in %s is vulnerable; minimum fixed version: %s", finding.Package, finding.Ecosystem, finding.FixedVersion)
		result := sarifResult{
			RuleID:  ruleID,
			Level:   "error",
			Message: sarifMessageFragment{Text: message},
			Properties: map[string]interface{}{
				"package":       finding.Package,
				"installed":     finding.Installed,
				"fixed_version": finding.FixedVersion,
				"ecosystem":     finding.Ecosystem,
			},
		}
		if len(finding.Locations) > 0 {
			uri := normalizeSARIFURI(repo, finding.Locations[0])
			if uri != "" {
				result.Locations = []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: uri},
					},
				}}
			}
		}
		results = append(results, result)
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, rulesByID[id])
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "PatchPilot",
				InformationURI: "https://github.com/moolen/PatchPilot",
				Rules:          rules,
			}},
			Results: results,
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: true,
			}},
		}},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif: %w", err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".patchpilot", sarifFile), data, 0o644); err != nil {
		return fmt.Errorf("write sarif report: %w", err)
	}
	return nil
}

func normalizeSARIFURI(repo, location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	if !filepath.IsAbs(location) {
		return filepath.ToSlash(filepath.Clean(location))
	}
	rel, err := filepath.Rel(repo, location)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(location))
	}
	return filepath.ToSlash(filepath.Clean(rel))
}
