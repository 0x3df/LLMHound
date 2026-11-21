package main

import (
	"fmt"
	"os"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/discovery"
	"github.com/0x3df/LLMHound/internal/scanner"
	"github.com/0x3df/LLMHound/internal/targets"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var version = "dev"

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use: "llmhound", Short: "LLMHound — AI infrastructure inventory for BloodHound",
		Long:    "LLMHound remotely maps the attack surface of LLM and agentic AI infrastructure\nfor BloodHound Community Edition.",
		Version: version, Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	root.CompletionOptions.DisableDefaultCmd = true
	var configPath string
	overrides := config.Defaults()
	flags := root.PersistentFlags()
	flags.StringVar(&configPath, "config", "llmhound.yaml", "Configuration file (default is optional; explicit path must exist)")
	flags.StringVar(&overrides.Scope, "scope", "", "Stable deployment/tenant scope (required)")
	flags.StringVar(&overrides.VantageKey, "vantage", "", "Stable scanner/network vantage key (required)")
	flags.StringSliceVar(&overrides.Targets, "targets", nil, "IP/FQDN/CIDR inputs; repeat or comma-separate (replaces targets)")
	flags.StringSliceVar(&overrides.CIDRs, "cidr", nil, "CIDR ranges; repeat or comma-separate (replaces cidrs)")
	flags.StringArrayVar(&overrides.TargetsFiles, "targets-file", nil, "Line-oriented targets file; repeat (replaces targets_files)")
	flags.StringSliceVar(&overrides.Exclude, "exclude", nil, "Exact IP/FQDN or CIDR exclusions; repeat or comma-separate")
	flags.StringArrayVar(&overrides.ExcludeFiles, "exclude-file", nil, "Line-oriented exclusions file; repeat (replaces exclude_files)")
	flags.IntVar(&overrides.Bounds.MaxTargets, "max-targets", overrides.Bounds.MaxTargets, "Maximum raw expansion before dedup/exclusions (1–65536)")
	flags.IntVar(&overrides.Bounds.Concurrency, "concurrency", overrides.Bounds.Concurrency, "Reserved collector concurrency (1–256)")
	flags.Float64Var(&overrides.Bounds.PerHostRate, "per-host-rate", overrides.Bounds.PerHostRate, "Reserved per-host requests/second (0.1–1000)")
	flags.DurationVar(&overrides.Bounds.ConnectTimeout, "connect-timeout", overrides.Bounds.ConnectTimeout, "Reserved connect timeout (1ms–5m)")
	flags.DurationVar(&overrides.Bounds.ResponseTimeout, "response-timeout", overrides.Bounds.ResponseTimeout, "Reserved response timeout (1ms–5m)")
	flags.Int64Var(&overrides.Bounds.MaxResponseBytes, "max-response-bytes", overrides.Bounds.MaxResponseBytes, "Reserved per-response byte limit (1–67108864)")
	flags.IntVar(&overrides.Bounds.MaxPages, "max-pages", overrides.Bounds.MaxPages, "Reserved per-check page limit (1–10000)")
	flags.IntVar(&overrides.Bounds.MaxItems, "max-items", overrides.Bounds.MaxItems, "Reserved per-check item limit (1–100000)")
	flags.IntVar(&overrides.Bounds.MaxRedirects, "max-redirects", overrides.Bounds.MaxRedirects, "Reserved authorized redirect limit (0–10)")
	flags.BoolVar(&overrides.Insecure, "insecure", false, "Reserved explicit TLS verification bypass (off by default)")
	flags.StringVar(&overrides.UserAgent, "user-agent", overrides.UserAgent, "Reserved identifiable request User-Agent")
	flags.BoolVar(&overrides.OptIns.ResourceContent, "resource-content", false, "Reserved sensitive resource-content opt-in")
	flags.BoolVar(&overrides.OptIns.Prompts, "prompts", false, "Reserved sensitive prompt-content opt-in")
	flags.BoolVar(&overrides.OptIns.ConfigurationContent, "configuration-content", false, "Reserved sensitive configuration-content opt-in")
	flags.BoolVar(&overrides.OptIns.WorkspaceContent, "workspace-content", false, "Reserved sensitive workspace-content opt-in")
	flags.StringVar(&overrides.Correlation.MappingFile, "mapping-file", "", "Asset mapping file from the normalizer: target to existing BloodHound objectid and kind")

	var prepared []string
	var effectiveConfig config.Config
	prepare := func(cmd *cobra.Command, _ []string) error {
		c := config.Defaults()
		// Missing implicit default is harmless; an explicit --config is never ignored.
		_, err := os.Stat(configPath)
		if err == nil || !os.IsNotExist(err) || flags.Changed("config") {
			c, err = config.Load(configPath)
			if err != nil {
				return err
			}
		}
		var changed []string
		flags.VisitAll(func(flag *pflag.Flag) {
			if flag.Changed && flag.Name != "config" {
				changed = append(changed, flag.Name)
			}
		})
		c, err = config.Apply(c, overrides, changed)
		if err != nil {
			return err
		}
		if err = c.Validate(); err != nil {
			return err
		}
		prepared, err = targets.Prepare(c.TargetInput())
		if err != nil {
			return err
		}
		if len(prepared) == 0 {
			return fmt.Errorf("no targets remain after exclusions")
		}
		effectiveConfig = c
		return nil
	}
	root.AddCommand(&cobra.Command{
		Use: "targets", Short: "Validate policy and print normalized targets offline (no traffic)",
		Long: "Validate scope, vantage and bounds, then print sorted, deduplicated targets\nafter exclusions. This is not the future targets × checks plan; no DNS or\nnetwork traffic occurs. Lists replace only their explicitly flagged field.",
		Args: cobra.NoArgs, PreRunE: prepare,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, target := range prepared {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), target); err != nil {
					return err
				}
			}
			return nil
		},
	})
	root.AddCommand(&cobra.Command{
		Use:     "plan",
		Short:   "Print planned targets × checks offline (no traffic)",
		Long:    "Prints the target hosts and allowlisted metadata checks planned for each\nsupported surface. No network traffic or DNS queries occur.",
		Args:    cobra.NoArgs,
		PreRunE: prepare,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := scanner.New(effectiveConfig, scanner.WithCollectorVersion(version))
			if err != nil {
				return err
			}
			plans := s.Plan(prepared)
			for _, tp := range plans {
				fmt.Fprintf(cmd.OutOrStdout(), "TARGET: %s\n", tp.Target)
				for _, sp := range tp.Surfaces {
					fmt.Fprintf(cmd.OutOrStdout(), "  SURFACE: %s (port %d)\n", sp.Surface, sp.Port)
					for _, chk := range sp.Checks {
						status := ""
						if !chk.Active {
							status = fmt.Sprintf(" [%s]", chk.SkipReason)
						}
						fmt.Fprintf(cmd.OutOrStdout(), "    - %s: %s (%s %s)%s\n", chk.CheckID, chk.Operation, chk.Method, chk.Endpoint, status)
					}
				}
			}
			return nil
		},
	})

	var outputDir string
	var artifactPrefix string
	var discoveryFile string

	scanCmd := &cobra.Command{
		Use:     "scan",
		Short:   "Remotely enumerate AI infrastructure across configured targets",
		Long:    "Discovers and enumerates AI services (Jupyter, MCP, Ollama) on prepared\ntargets, writing through a checkpoint journal and emitting OpenGraph JSON\nand evidence sidecar files.",
		Args:    cobra.NoArgs,
		PreRunE: prepare,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var scanOpts []scanner.Option
			scanOpts = append(scanOpts, scanner.WithCollectorVersion(version))
			if discoveryFile != "" {
				defs, err := discovery.LoadDefinitionsFile(discoveryFile)
				if err != nil {
					return fmt.Errorf("load discovery definitions: %w", err)
				}
				scanOpts = append(scanOpts, scanner.WithDefinitions(defs))
			}
			s, err := scanner.New(effectiveConfig, scanOpts...)
			if err != nil {
				return err
			}
			res, err := s.Scan(cmd.Context(), prepared, outputDir, artifactPrefix)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Scan completed for %d target(s)\n", res.TargetsCount)
			fmt.Fprintf(cmd.OutOrStdout(), "  Base payload: %s\n", res.Artifacts.BasePayloadPath)
			if res.Artifacts.LinkingPayloadPath != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  Linking payload: %s\n", res.Artifacts.LinkingPayloadPath)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  Evidence sidecar: %s\n", res.Artifacts.EvidenceSidecarPath)
			fmt.Fprintf(cmd.OutOrStdout(), "  Checkpoint journal: %s\n", res.JournalPath)
			return nil
		},
	}
	scanCmd.Flags().StringVar(&outputDir, "output-dir", "", "Directory to write emitted scan artifacts (default: current directory)")
	scanCmd.Flags().StringVar(&artifactPrefix, "prefix", "", "Filename prefix for emitted scan artifacts (default: llmhound-<timestamp>)")
	scanCmd.Flags().StringVar(&discoveryFile, "discovery-file", "", "Optional custom discovery fingerprint definitions file")
	root.AddCommand(scanCmd)

	root.AddCommand(&cobra.Command{
		Use: "upload", Short: "upload (not implemented; reserved for M3)", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("upload is not implemented (M3); no CE API calls were made")
		},
	})
	return root
}
