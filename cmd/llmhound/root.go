package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0x3df/LLMHound/extension"
	"github.com/0x3df/LLMHound/internal/bloodhound"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/discovery"
	"github.com/0x3df/LLMHound/internal/rules"
	"github.com/0x3df/LLMHound/internal/savedsearch"
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
	var disabledContentSurfaces []string
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
	flags.IntVar(&overrides.Bounds.Concurrency, "concurrency", overrides.Bounds.Concurrency, "Worker concurrency (1–256)")
	flags.Float64Var(&overrides.Bounds.PerHostRate, "per-host-rate", overrides.Bounds.PerHostRate, "Per-host requests/second (0.1–1000)")
	flags.DurationVar(&overrides.Bounds.ConnectTimeout, "connect-timeout", overrides.Bounds.ConnectTimeout, "Connect timeout (1ms–5m)")
	flags.DurationVar(&overrides.Bounds.ResponseTimeout, "response-timeout", overrides.Bounds.ResponseTimeout, "Response timeout (1ms–5m)")
	flags.Int64Var(&overrides.Bounds.MaxResponseBytes, "max-response-bytes", overrides.Bounds.MaxResponseBytes, "Per-response byte limit (1–67108864)")
	flags.IntVar(&overrides.Bounds.MaxPages, "max-pages", overrides.Bounds.MaxPages, "Per-check page limit (1–10000)")
	flags.IntVar(&overrides.Bounds.MaxItems, "max-items", overrides.Bounds.MaxItems, "Per-check item limit (1–100000)")
	flags.IntVar(&overrides.Bounds.MaxRedirects, "max-redirects", overrides.Bounds.MaxRedirects, "Authorized redirect limit (0–10)")
	flags.BoolVar(&overrides.Insecure, "insecure", false, "Explicit TLS verification bypass (off by default)")
	flags.StringVar(&overrides.UserAgent, "user-agent", overrides.UserAgent, "Identifiable request User-Agent")
	flags.BoolVar(&overrides.Content.Enabled, "content", overrides.Content.Enabled, "Collect allowlisted anonymous content bodies into .content.jsonl")
	flags.Int64Var(&overrides.Content.MaxItemBytes, "content-max-item-bytes", overrides.Content.MaxItemBytes, "Maximum bytes retained per content item (1–16777216)")
	flags.IntVar(&overrides.Content.MaxItemsPerResource, "content-max-items-per-resource", overrides.Content.MaxItemsPerResource, "Maximum content items per resource (1–1000)")
	flags.Int64Var(&overrides.Content.MaxServiceBytes, "content-max-service-bytes", overrides.Content.MaxServiceBytes, "Maximum content bytes per service (1–268435456)")
	flags.IntVar(&overrides.Content.MaxSamplePoints, "content-max-sample-points", overrides.Content.MaxSamplePoints, "Maximum sample points per vector collection (1–1000)")
	flags.StringSliceVar(&disabledContentSurfaces, "content-disable", nil, "Disable content-tier reads for named surfaces (comma-separated or repeated)")
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
		if flags.Changed("content-disable") {
			overrides.Content.Surfaces = make(map[string]bool, len(disabledContentSurfaces))
			for _, s := range disabledContentSurfaces {
				overrides.Content.Surfaces[strings.TrimSpace(s)] = false
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
		Long:    "Discovers and enumerates AI services (Jupyter, MCP, Ollama, A2A, vLLM, Qdrant, LiteLLM,\nMLflow, Open WebUI, LangServe, Generic OpenAI-compatible, Ray, Langflow, Flowise, ChromaDB)\non prepared targets, writing through a checkpoint journal and emitting OpenGraph JSON\nand evidence sidecar files.",
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
			printScanSummary(cmd, "Scan", res)
			return nil
		},
	}
	scanCmd.Flags().StringVar(&outputDir, "output-dir", "", "Directory to write emitted scan artifacts (default: current directory)")
	scanCmd.Flags().StringVar(&artifactPrefix, "prefix", "", "Filename prefix for emitted scan artifacts (default: llmhound-<timestamp>)")
	scanCmd.Flags().StringVar(&discoveryFile, "discovery-file", "", "Optional custom discovery fingerprint definitions file")
	root.AddCommand(scanCmd)

	var resumeJournalPath string
	var resumeOutputDir string
	var resumePrefix string
	var resumeDiscoveryFile string

	resumeCmd := &cobra.Command{
		Use:     "resume",
		Short:   "Resume an interrupted scan from a checkpoint journal",
		Long:    "Replays an existing checkpoint journal, repairs any torn tail line, skips\nalready-completed (target, surface) pairs, collects remaining work, and\nre-emits OpenGraph JSON, evidence sidecar, and content artifacts.",
		Args:    cobra.NoArgs,
		PreRunE: prepare,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(resumeJournalPath) == "" {
				return fmt.Errorf("--journal is required")
			}
			var scanOpts []scanner.Option
			scanOpts = append(scanOpts, scanner.WithCollectorVersion(version))
			if resumeDiscoveryFile != "" {
				defs, err := discovery.LoadDefinitionsFile(resumeDiscoveryFile)
				if err != nil {
					return fmt.Errorf("load discovery definitions: %w", err)
				}
				scanOpts = append(scanOpts, scanner.WithDefinitions(defs))
			}
			s, err := scanner.New(effectiveConfig, scanOpts...)
			if err != nil {
				return err
			}
			res, err := s.Resume(cmd.Context(), resumeJournalPath, prepared, resumeOutputDir, resumePrefix)
			if err != nil {
				return err
			}
			printScanSummary(cmd, "Resume", res)
			return nil
		},
	}
	resumeCmd.Flags().StringVar(&resumeJournalPath, "journal", "", "Path to existing .journal.jsonl file (required)")
	resumeCmd.Flags().StringVar(&resumeOutputDir, "output-dir", "", "Directory to write resumed scan artifacts (default: journal directory)")
	resumeCmd.Flags().StringVar(&resumePrefix, "prefix", "", "Filename prefix for resumed artifacts (default: derived from journal filename)")
	resumeCmd.Flags().StringVar(&resumeDiscoveryFile, "discovery-file", "", "Optional custom discovery fingerprint definitions file")
	root.AddCommand(resumeCmd)

	var (
		bhURL             string
		bhTokenID         string
		bhTokenKey        string
		bhBearerToken     string
		bhUsername        string
		bhPassword        string
		baseFile          string
		linkingFile       string
		registerSchema    bool
		enableRulesSchema bool
		importQueries     bool
		queriesDir        string
		includeCanExec    bool
		validateOnly      bool
		allowUnvalidated  bool
		uploadTimeout     time.Duration
		pollInterval      time.Duration
		maxRetries        int
		insecureCE        bool
	)

	uploadCmd := &cobra.Command{
		Use:   "upload",
		Short: "Validate BloodHound CE adapter, register schema, upload OpenGraph payloads, and import saved queries",
		Long:  "Runs the M3 BloodHound CE validation gate, registers the LLMHound extension schema,\nperforms M0 Q5 two-step upload (with read-only Cypher existence pre-flight for linking\npayloads), and imports saved searches into BloodHound CE.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedURL := firstNonEmpty(bhURL, os.Getenv("BLOODHOUND_URL"))
			auth := bloodhound.AuthConfig{
				TokenID:     firstNonEmpty(bhTokenID, os.Getenv("BLOODHOUND_TOKEN_ID")),
				TokenKey:    firstNonEmpty(bhTokenKey, os.Getenv("BLOODHOUND_TOKEN_KEY")),
				BearerToken: firstNonEmpty(bhBearerToken, os.Getenv("BLOODHOUND_BEARER_TOKEN")),
				Username:    firstNonEmpty(bhUsername, os.Getenv("BLOODHOUND_USERNAME")),
				Password:    firstNonEmpty(bhPassword, os.Getenv("BLOODHOUND_PASSWORD")),
			}

			client, err := bloodhound.NewClient(bloodhound.ClientConfig{
				BaseURL:   resolvedURL,
				Auth:      auth,
				Timeout:   uploadTimeout,
				Insecure:  insecureCE,
				UserAgent: "LLMHound/" + version,
			})
			if err != nil {
				return err
			}

			if !validateOnly && !registerSchema && baseFile == "" && linkingFile == "" && !importQueries {
				return fmt.Errorf("nothing to do: specify at least one of --validate-only, --register-schema, --base-file, --linking-file, or --import-queries")
			}

			ctx := cmd.Context()
			gate, err := client.ValidateAdapter(ctx, allowUnvalidated)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "BloodHound CE %s (%s) adapter gate passed\n", gate.ServerVersion, gate.Edition)
			for _, chk := range gate.Checks {
				if chk.Warning != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  WARNING [%s]: %s\n", chk.Name, chk.Warning)
				}
			}

			if validateOnly {
				return nil
			}

			if registerSchema {
				schemaBytes := extension.SchemaJSON
				if enableRulesSchema {
					schemaBytes, err = rules.SchemaWithCanExecuteOn(schemaBytes)
					if err != nil {
						return fmt.Errorf("build rules schema extension: %w", err)
					}
				}
				if err := client.RegisterExtension(ctx, schemaBytes); err != nil {
					return fmt.Errorf("register extension schema: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Extension schema registered (rules_schema=%v)\n", enableRulesSchema)
			}

			if baseFile != "" || linkingFile != "" {
				var opts bloodhound.UploadOptions
				opts.PollInterval = pollInterval
				opts.PollTimeout = uploadTimeout
				opts.MaxRetries = maxRetries
				if baseFile != "" {
					b, err := os.ReadFile(baseFile)
					if err != nil {
						return fmt.Errorf("read base file %q: %w", baseFile, err)
					}
					opts.BasePayloadBytes = b
					opts.BaseFileName = filepath.Base(baseFile)
				}
				if linkingFile != "" {
					b, err := os.ReadFile(linkingFile)
					if err != nil {
						return fmt.Errorf("read linking file %q: %w", linkingFile, err)
					}
					opts.LinkingPayloadBytes = b
					opts.LinkingFileName = filepath.Base(linkingFile)
				}
				rep, err := client.UploadScan(ctx, opts)
				if err != nil {
					return err
				}
				if rep.BaseJob != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "  Base payload uploaded: job=%d status=%d attempts=%d\n", rep.BaseJob.JobID, rep.BaseJob.Status, rep.BaseJob.Attempts)
				}
				if linkingFile != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  Linking pre-flight: kept=%d skipped=%d\n", rep.KeptEdges, len(rep.SkippedEdges))
					for _, sk := range rep.SkippedEdges {
						fmt.Fprintf(cmd.OutOrStdout(), "    SKIP edge %s %s -> %s: %s\n", sk.Kind, sk.StartID, sk.EndID, sk.Reason)
					}
					if rep.LinkingJob != nil {
						fmt.Fprintf(cmd.OutOrStdout(), "  Linking payload uploaded: job=%d status=%d attempts=%d\n", rep.LinkingJob.JobID, rep.LinkingJob.Status, rep.LinkingJob.Attempts)
					}
				}
			}

			if importQueries {
				var queries []savedsearch.Query
				if queriesDir != "" {
					queries, err = loadQueriesDir(queriesDir)
					if err != nil {
						return err
					}
				} else {
					kinds, err := client.TraversablePathKinds(ctx, includeCanExec)
					if err != nil {
						return fmt.Errorf("discover traversable path kinds: %w", err)
					}
					if len(kinds) == 0 {
						return fmt.Errorf("no traversable path kinds reported by BloodHound CE; pass --queries-dir or register extension edges first")
					}
					queries = savedsearch.GenerateWithOptions(kinds, savedsearch.GenerateOptions{
						IncludeCanExecuteOn: includeCanExec,
					})
				}
				n, err := client.ImportSavedQueries(ctx, queries)
				if err != nil {
					return fmt.Errorf("import saved queries: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  Imported %d saved queries into BloodHound CE\n", n)
			}

			return nil
		},
	}
	uploadCmd.Flags().StringVar(&bhURL, "url", "", "BloodHound CE base URL (or BLOODHOUND_URL)")
	uploadCmd.Flags().StringVar(&bhTokenID, "token-id", "", "BloodHound HMAC Token ID (or BLOODHOUND_TOKEN_ID)")
	uploadCmd.Flags().StringVar(&bhTokenKey, "token-key", "", "BloodHound HMAC Token Key (or BLOODHOUND_TOKEN_KEY)")
	uploadCmd.Flags().StringVar(&bhBearerToken, "bearer-token", "", "BloodHound Bearer JWT (or BLOODHOUND_BEARER_TOKEN)")
	uploadCmd.Flags().StringVar(&bhUsername, "username", "", "BloodHound username for login (or BLOODHOUND_USERNAME)")
	uploadCmd.Flags().StringVar(&bhPassword, "password", "", "BloodHound password for login (or BLOODHOUND_PASSWORD)")
	uploadCmd.Flags().StringVar(&baseFile, "base-file", "", "Path to base OpenGraph JSON payload (with source_kind: LLMHound)")
	uploadCmd.Flags().StringVar(&linkingFile, "linking-file", "", "Path to sourceless linking OpenGraph JSON payload")
	uploadCmd.Flags().BoolVar(&registerSchema, "register-schema", false, "Register the embedded LLMHound extension schema before uploading")
	uploadCmd.Flags().BoolVar(&enableRulesSchema, "enable-rules-schema", false, "When registering schema, include opt-in traversable LLMHound_CanExecuteOn")
	uploadCmd.Flags().BoolVar(&importQueries, "import-queries", false, "Import LLMHound saved queries into BloodHound CE")
	uploadCmd.Flags().StringVar(&queriesDir, "queries-dir", "", "Directory of saved-query JSON files to import (default: generate from CE traversable path kinds)")
	uploadCmd.Flags().BoolVar(&includeCanExec, "include-can-execute-on", false, "Include LLMHound_CanExecuteOn when generating saved queries")
	uploadCmd.Flags().BoolVar(&validateOnly, "validate-only", false, "Run the BloodHound CE adapter validation gate and exit")
	uploadCmd.Flags().BoolVar(&allowUnvalidated, "allow-unvalidated-ce", false, "Allow non-pinned CE version with a warning (off by default)")
	uploadCmd.Flags().DurationVar(&uploadTimeout, "timeout", 5*time.Minute, "HTTP request and upload job poll timeout")
	uploadCmd.Flags().DurationVar(&pollInterval, "poll-interval", 1*time.Second, "Upload job status polling interval")
	uploadCmd.Flags().IntVar(&maxRetries, "max-retries", 2, "Retries on canceled upload jobs")
	uploadCmd.Flags().BoolVar(&insecureCE, "insecure-ce", false, "Bypass TLS verification for BloodHound CE API (explicit opt-in; off by default)")
	root.AddCommand(uploadCmd)
	return root
}

func printScanSummary(cmd *cobra.Command, verb string, res *scanner.ScanResult) {
	fmt.Fprintf(cmd.OutOrStdout(), "%s completed for %d target(s)\n", verb, res.TargetsCount)
	fmt.Fprintf(cmd.OutOrStdout(), "  Base payload: %s\n", res.Artifacts.BasePayloadPath)
	if res.Artifacts.LinkingPayloadPath != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "  Linking payload: %s\n", res.Artifacts.LinkingPayloadPath)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  Evidence sidecar: %s\n", res.Artifacts.EvidenceSidecarPath)
	fmt.Fprintf(cmd.OutOrStdout(), "  Checkpoint journal: %s\n", res.JournalPath)
	if res.ContentPath != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "  Content file: %s\n", res.ContentPath)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func loadQueriesDir(dir string) ([]savedsearch.Query, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read queries directory %q: %w", dir, err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("no .json saved query files found in %q", dir)
	}
	out := make([]savedsearch.Query, 0, len(names))
	for _, name := range names {
		p := filepath.Join(dir, name)
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read saved query %q: %w", p, err)
		}
		var q savedsearch.Query
		if err := json.Unmarshal(raw, &q); err != nil {
			return nil, fmt.Errorf("decode saved query %q: %w", p, err)
		}
		if strings.TrimSpace(q.Name) == "" || strings.TrimSpace(q.Query) == "" {
			return nil, fmt.Errorf("saved query %q missing name or query", p)
		}
		out = append(out, q)
	}
	return out, nil
}
