package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/runresult"
	"github.com/0x3df/LLMHound/internal/scanner"
	"github.com/spf13/cobra"
)

func startResultTracker(cmd *cobra.Command, command runresult.Command, resultFile string, mutate func(*runresult.Result)) (*runresult.Tracker, error) {
	if !cmd.Flags().Changed("result-file") && resultFile == "" {
		return nil, nil
	}
	tr, err := runresult.NewTracker(resultFile, command, version, nil)
	if err != nil {
		return nil, err
	}
	if err := tr.StartPending(mutate); err != nil {
		return nil, err
	}
	return tr, nil
}

func finishTracker(tracker *runresult.Tracker, ctxErr, runErr error, mutate func(*runresult.Result)) error {
	if tracker == nil {
		return runErr
	}
	status := runresult.ClassifyStatus(ctxErr, runErr)
	exitCode := 0
	errMsg := ""
	if status != runresult.StatusComplete {
		exitCode = 1
		errMsg = runErr.Error()
	}
	if writeErr := tracker.Finish(status, exitCode, errMsg, mutate); writeErr != nil {
		if runErr == nil {
			return fmt.Errorf("write result file: %w", writeErr)
		}
		return errors.Join(runErr, fmt.Errorf("write result file: %w", writeErr))
	}
	return runErr
}

func checkScanResultCollisions(resultFile, outputDir, prefix, existingJournal string) error {
	if strings.TrimSpace(resultFile) == "" {
		return nil
	}
	if runresult.PathCollides(resultFile, existingJournal) {
		return fmt.Errorf("result-file %q cannot collide with journal %q", resultFile, existingJournal)
	}
	if prefix != "" {
		dir := outputDir
		if dir == "" {
			dir = "."
		}
		for _, suffix := range []string{".json", "-base.json", "-linking.json", ".evidence.jsonl", ".journal.jsonl", ".content.jsonl"} {
			candidate := filepath.Join(dir, prefix+suffix)
			if runresult.PathCollides(resultFile, candidate) {
				return fmt.Errorf("result-file %q cannot collide with scan artifact %q", resultFile, candidate)
			}
		}
	}
	return nil
}

func checkUploadResultCollisions(resultFile, baseFile, linkingFile string) error {
	if strings.TrimSpace(resultFile) == "" {
		return nil
	}
	for _, in := range []string{baseFile, linkingFile} {
		if runresult.PathCollides(resultFile, in) {
			return fmt.Errorf("result-file %q cannot collide with input payload %q", resultFile, in)
		}
	}
	return nil
}

func effectiveContentMode(c config.Config) string {
	if !c.Content.Enabled {
		return "disabled"
	}
	return c.Content.Mode
}

func journalExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func populateScanSection(sec *runresult.ScanSection, res *scanner.ScanResult) {
	if sec == nil || res == nil {
		return
	}
	sec.ScanID = res.ScanID
	sec.Prefix = res.Prefix
	sec.OutputDir = res.OutputDir
	tc := res.TargetsCount
	sec.TargetsCount = &tc
	sec.Artifacts = runresult.ScanArtifacts{
		BasePayloadPath:     res.Artifacts.BasePayloadPath,
		LinkingPayloadPath:  res.Artifacts.LinkingPayloadPath,
		EvidenceSidecarPath: res.Artifacts.EvidenceSidecarPath,
		JournalPath:         res.JournalPath,
		ContentPath:         res.ContentPath,
	}
	sec.TargetErrorCount = res.TargetErrorCount
	if len(res.TargetErrors) > 0 {
		limit := len(res.TargetErrors)
		if limit > runresult.MaxRetainedTargetErrors {
			limit = runresult.MaxRetainedTargetErrors
		}
		sec.TargetErrors = append([]string(nil), res.TargetErrors[:limit]...)
		sec.TargetErrorsTruncated = res.TargetErrorCount > limit
	} else {
		sec.TargetErrors = nil
		sec.TargetErrorsTruncated = false
	}
	if res.Emitted {
		sec.Counts = &runresult.ScanCounts{
			Services:              res.ServicesCount,
			BaseNodes:             res.BaseNodesCount,
			BaseEdges:             res.BaseEdgesCount,
			LinkingEdges:          res.LinkingEdgesCount,
			EvidenceRecords:       res.EvidenceRecordsCount,
			ExposedSecretServices: res.ExposedSecretServicesCount,
		}
	}
}
