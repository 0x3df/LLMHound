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
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/discovery"
	"github.com/0x3df/LLMHound/internal/rules"
	"github.com/0x3df/LLMHound/internal/runresult"
	"github.com/0x3df/LLMHound/internal/savedsearch"
	"github.com/0x3df/LLMHound/internal/scanner"
	"github.com/0x3df/LLMHound/internal/targets"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

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
	var prettyJSON bool
	overrides := config.Defaults()
	flags := root.PersistentFlags()
	flags.StringVar(&configPath, "config", "llmhound.yaml", "Configuration file (default is optional; explicit path must exist)")
	flags.StringVar(&overrides.Scope, "scope", "", "Stable deployment/tenant scope (required)")
	flags.StringVar(&overrides.VantageKey, "vantage", "", "Stable scanner/network vantage key (required)")
	flags.StringSliceVar(&overrides.Targets, "targets", nil, "IP/FQDN/CIDR inputs; repeat or comma-separate (replaces targets)")
	flags.StringSliceVar(&overrides.CIDRs, "cidr", nil, "CIDR ranges; repeat or comma-separate (replaces cidrs)")
	flags.StringArrayVar(&overrides.TargetsFiles, "targets-file", nil, "Line-oriented targets file; repeat (replaces targets_files)")
	flags.StringArrayVar(&overrides.EndpointsFiles, "endpoints-file", nil, "Line-oriented host:port or scheme://host:port file; repeat (replaces endpoints_files)")
	flags.StringSliceVar(&overrides.Exclude, "exclude", nil, "Exact IP/FQDN or CIDR exclusions; repeat or comma-separate")
	flags.StringArrayVar(&overrides.ExcludeFiles, "exclude-file", nil, "Line-oriented exclusions file; repeat (replaces exclude_files)")
	flags.IntVar(&overrides.Bounds.MaxTargets, "max-targets", overrides.Bounds.MaxTargets, "Maximum raw expansion before dedup/exclusions (1–1048576)")
	flags.IntVar(&overrides.Bounds.Concurrency, "concurrency", overrides.Bounds.Concurrency, "Worker concurrency (1–1024)")
	flags.IntVar(&overrides.Bounds.TCPConcurrency, "tcp-concurrency", overrides.Bounds.TCPConcurrency, "Stage 1 TCP open-port sweep concurrency (1–4096)")
	flags.DurationVar(&overrides.Bounds.TCPTimeout, "tcp-timeout", overrides.Bounds.TCPTimeout, "Stage 1 TCP dial timeout (50ms–30s)")
	flags.Float64Var(&overrides.Bounds.PerHostRate, "per-host-rate", overrides.Bounds.PerHostRate, "Per-host requests/second (0.1–1000)")
	flags.DurationVar(&overrides.Bounds.ConnectTimeout, "connect-timeout", overrides.Bounds.ConnectTimeout, "Connect timeout (1ms–5m)")
	flags.DurationVar(&overrides.Bounds.ResponseTimeout, "response-timeout", overrides.Bounds.ResponseTimeout, "Response timeout (1ms–5m)")
	flags.Int64Var(&overrides.Bounds.MaxResponseBytes, "max-response-bytes", overrides.Bounds.MaxResponseBytes, "Per-response byte limit (1–67108864)")
	flags.IntVar(&overrides.Bounds.MaxPages, "max-pages", overrides.Bounds.MaxPages, "Per-check page limit (1–10000)")
	flags.IntVar(&overrides.Bounds.MaxItems, "max-items", overrides.Bounds.MaxItems, "Per-check item limit (1–100000)")
	flags.IntVar(&overrides.Bounds.MaxRedirects, "max-redirects", overrides.Bounds.MaxRedirects, "Authorized redirect limit (0–10)")
	flags.StringVar(&overrides.Scan.Profile, "profile", overrides.Scan.Profile, "Discovery profile: attack-path, rce-only, or full")
	flags.StringSliceVar(&overrides.Scan.Surfaces, "surfaces", nil, "Explicit comma-separated surfaces to scan (overrides profile)")
	flags.StringVar(&overrides.Scan.GraphMode, "graph-mode", overrides.Scan.GraphMode, "BloodHound graph emission mode: attack-path or full")
	flags.StringVar(&overrides.Scan.Scheme, "scheme", overrides.Scan.Scheme, "Discovery scheme: auto, http, or https")
	flags.BoolVar(&overrides.Scan.RecordUnmatched, "record-unmatched", overrides.Scan.RecordUnmatched, "Record failed journal/evidence rows for unreachable ports")
	flags.BoolVar(&prettyJSON, "pretty-json", false, "Emit indented OpenGraph JSON (default is compact JSON)")
	flags.BoolVar(&overrides.Scan.MappedOnly, "mapped-only", overrides.Scan.MappedOnly, "Omit unmapped NetworkEndpoint nodes from BloodHound payloads")
	flags.BoolVar(&overrides.Scan.MappedOnlyTargets, "mapped-only-targets", overrides.Scan.MappedOnlyTargets, "Restrict scan targets strictly to hosts in correlation.mapping_file")
	flags.IntSliceVar(&overrides.Scan.ExtraPorts, "extra-ports", nil, "Additional TCP ports to sweep/probe across active surfaces")
	flags.BoolVar(&overrides.Insecure, "insecure", false, "Explicit TLS verification bypass (off by default)")
	flags.StringVar(&overrides.Proxy, "proxy", "", "Explicit http://, https://, or socks5:// proxy for scan traffic (HTTP_PROXY/HTTPS_PROXY are ignored)")
	flags.StringVar(&overrides.UserAgent, "user-agent", overrides.UserAgent, "Identifiable request User-Agent")
	flags.BoolVar(&overrides.Content.Enabled, "content", overrides.Content.Enabled, "Enable bounded allowlisted content-tier reads")
	flags.StringVar(&overrides.Content.Mode, "content-mode", overrides.Content.Mode, "Content-tier mode: secrets-only, metadata, or full")
	flags.Int64Var(&overrides.Content.MaxItemBytes, "content-max-item-bytes", overrides.Content.MaxItemBytes, "Maximum bytes retained per content item (1–16777216)")
	flags.IntVar(&overrides.Content.MaxItemsPerResource, "content-max-items-per-resource", overrides.Content.MaxItemsPerResource, "Maximum content items per resource (1–1000)")
	flags.Int64Var(&overrides.Content.MaxServiceBytes, "content-max-service-bytes", overrides.Content.MaxServiceBytes, "Maximum content bytes per service (1–268435456)")
	flags.IntVar(&overrides.Content.MaxSamplePoints, "content-max-sample-points", overrides.Content.MaxSamplePoints, "Maximum sample points per vector collection (1–1000)")
	flags.StringSliceVar(&disabledContentSurfaces, "content-disable", nil, "Disable content-tier reads for named surfaces (comma-separated or repeated)")
	flags.StringVar(&overrides.Correlation.MappingFile, "mapping-file", "", "Asset mapping file from the normalizer: target to existing BloodHound objectid and kind")

	var prepared []string
	var preparedEndpoints []targets.EndpointTarget
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
		if flags.Changed("pretty-json") {
			overrides.Scan.CompactJSON = !prettyJSON
		}
		var changed []string
		flags.VisitAll(func(flag *pflag.Flag) {
			if !flag.Changed || flag.Name == "config" {
				return
			}
			if flag.Name == "pretty-json" {
				changed = append(changed, "compact-json")
				return
			}
			changed = append(changed, flag.Name)
		})
		c, err = config.Apply(c, overrides, changed)
		if err != nil {
			return err
		}
		// An unset User-Agent identifies the actual build, not "dev".
		if c.UserAgent == config.DefaultUserAgent {
			c.UserAgent = "LLMHound/" + version
		}
		if err = c.Validate(); err != nil {
			return err
		}
		ti := c.TargetInput()
		if len(ti.Entries) > 0 || len(ti.Files) > 0 {
			prepared, err = targets.Prepare(ti)
			if err != nil {
				return err
			}
		} else {
			prepared = nil
		}
		if len(c.EndpointsFiles) > 0 {
			preparedEndpoints, err = targets.PrepareEndpoints(nil, c.EndpointsFiles, c.Exclude, c.ExcludeFiles, c.Bounds.MaxTargets)
			if err != nil {
				return err
			}
		} else {
			preparedEndpoints = nil
		}
		if len(prepared) == 0 && len(preparedEndpoints) == 0 {
			return fmt.Errorf("no targets remain after exclusions")
		}
		effectiveConfig = c
		return nil
	}

	var prioOpts bhSeedOptions
	targetsCmd := &cobra.Command{
		Use: "targets", Short: "Validate policy and print normalized targets (offline unless --prioritize-from-bh)",
		Long: "Validate scope, vantage and bounds, then print sorted, deduplicated targets\nafter exclusions. No target network traffic occurs.",
		Args: cobra.NoArgs, PreRunE: prepare,
		RunE: func(cmd *cobra.Command, _ []string) error {
			outTargets := prepared
			if effectiveConfig.Correlation.MappingFile != "" || prioOpts.enabled {
				resolver, err := correlate.NewFromConfig(effectiveConfig)
				if err != nil {
					return err
				}
				var prioIDs map[string]bool
				if prioOpts.enabled {
					prioIDs, err = fetchTier0PriorityIDs(cmd, prioOpts)
					if err != nil {
						return err
					}
				}
				outTargets = targets.PrioritizeTargets(prepared, resolver.ObjectIDForTarget, prioIDs, effectiveConfig.Scan.MappedOnlyTargets)
			}
			for _, target := range outTargets {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), target); err != nil {
					return err
				}
			}
			for _, ep := range preparedEndpoints {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), ep.String()); err != nil {
					return err
				}
			}
			return nil
		},
	}
	bindBHSeedFlags(targetsCmd, &prioOpts)
	root.AddCommand(targetsCmd)
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

	var progressInterval time.Duration
	withProgress := func(cmd *cobra.Command, opts []scanner.Option) []scanner.Option {
		if progressInterval > 0 {
			opts = append(opts, scanner.WithProgress(cmd.ErrOrStderr(), progressInterval))
		}
		return opts
	}

	var outputDir string
	var artifactPrefix string
	var discoveryFile string
	var scanResultFile string
	var scanBHOpts bhSeedOptions

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Remotely enumerate AI infrastructure across configured targets",
		Long:  "Discovers and enumerates AI services (Jupyter, MCP, Ollama, A2A, vLLM, Qdrant, LiteLLM,\nMLflow, Open WebUI, LangServe, Generic OpenAI-compatible, Ray, Langflow, Flowise, ChromaDB)\non prepared targets, writing through a checkpoint journal and emitting OpenGraph JSON\nand evidence sidecar files.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkScanResultCollisions(scanResultFile, outputDir, artifactPrefix, ""); err != nil {
				return err
			}
			scanSec := runresult.ScanSection{
				Prefix:    artifactPrefix,
				OutputDir: outputDir,
			}
			tracker, err := startResultTracker(cmd, runresult.CommandScan, scanResultFile, func(r *runresult.Result) {
				cp := scanSec
				r.Scan = &cp
			})
			if err != nil {
				return err
			}
			fail := func(runErr error) error {
				return finishTracker(tracker, cmd.Context().Err(), runErr, func(r *runresult.Result) {
					cp := scanSec
					r.Scan = &cp
				})
			}

			if err := prepare(cmd, args); err != nil {
				return fail(err)
			}
			scanSec.Scope = effectiveConfig.Scope
			scanSec.VantageKey = effectiveConfig.VantageKey
			scanSec.Profile = effectiveConfig.Scan.Profile
			scanSec.GraphMode = effectiveConfig.Scan.GraphMode
			scanSec.ContentMode = effectiveContentMode(effectiveConfig)

			var scanOpts []scanner.Option
			scanOpts = append(scanOpts, scanner.WithCollectorVersion(version))
			if discoveryFile != "" {
				defs, err := discovery.LoadDefinitionsFile(discoveryFile)
				if err != nil {
					return fail(fmt.Errorf("load discovery definitions: %w", err))
				}
				scanOpts = append(scanOpts, scanner.WithDefinitions(defs))
			}
			if len(preparedEndpoints) > 0 {
				scanOpts = append(scanOpts, scanner.WithEndpoints(preparedEndpoints))
			}
			if scanBHOpts.enabled {
				ids, err := fetchTier0PriorityIDs(cmd, scanBHOpts)
				if err != nil {
					return fail(err)
				}
				scanOpts = append(scanOpts, scanner.WithPriorityObjectIDs(ids))
			}
			if tracker != nil {
				scanOpts = append(scanOpts, scanner.WithOnStart(func(st scanner.ScanStart) error {
					if err := checkScanResultCollisions(scanResultFile, st.OutputDir, st.Prefix, st.JournalPath); err != nil {
						return err
					}
					tc := st.TargetsCount
					scanSec.ScanID = st.ScanID
					scanSec.Prefix = st.Prefix
					scanSec.OutputDir = st.OutputDir
					scanSec.TargetsCount = &tc
					scanSec.Artifacts.JournalPath = st.JournalPath
					return tracker.UpdatePending(func(r *runresult.Result) {
						cp := scanSec
						r.Scan = &cp
					})
				}))
			}
			s, err := scanner.New(effectiveConfig, withProgress(cmd, scanOpts)...)
			if err != nil {
				return fail(err)
			}
			res, err := s.Scan(cmd.Context(), prepared, outputDir, artifactPrefix)
			if res != nil {
				populateScanSection(&scanSec, res)
			}
			if err != nil {
				scanSec.Resumable = journalExists(scanSec.Artifacts.JournalPath)
				return fail(err)
			}
			if sumErr := printScanSummary(cmd, "Scan", res); sumErr != nil {
				scanSec.Resumable = journalExists(scanSec.Artifacts.JournalPath)
				return fail(sumErr)
			}
			scanSec.Resumable = false
			return finishTracker(tracker, cmd.Context().Err(), nil, func(r *runresult.Result) {
				cp := scanSec
				r.Scan = &cp
			})
		},
	}
	scanCmd.Flags().StringVar(&outputDir, "output-dir", "", "Directory to write emitted scan artifacts (default: current directory)")
	scanCmd.Flags().StringVar(&artifactPrefix, "prefix", "", "Filename prefix for emitted scan artifacts (default: llmhound-<timestamp>)")
	scanCmd.Flags().StringVar(&discoveryFile, "discovery-file", "", "Optional custom discovery fingerprint definitions file")
	scanCmd.Flags().DurationVar(&progressInterval, "progress-interval", 30*time.Second, "Print a progress line to stderr at this interval (0 disables)")
	scanCmd.Flags().StringVar(&scanResultFile, "result-file", "", "Optional path to write a machine-readable JSON lifecycle result file")
	bindBHSeedFlags(scanCmd, &scanBHOpts)
	root.AddCommand(scanCmd)

	var resumeJournalPath string
	var resumeOutputDir string
	var resumePrefix string
	var resumeDiscoveryFile string
	var resumeResultFile string

	resumeCmd := &cobra.Command{
		Use:   "resume",
		Short: "Resume an interrupted scan from a checkpoint journal",
		Long:  "Replays an existing checkpoint journal, repairs any torn tail line, skips\nalready-completed (target, surface) pairs, collects remaining work, and\nre-emits OpenGraph JSON, evidence sidecar, and content artifacts.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkScanResultCollisions(resumeResultFile, resumeOutputDir, resumePrefix, resumeJournalPath); err != nil {
				return err
			}
			scanSec := runresult.ScanSection{
				Prefix:    resumePrefix,
				OutputDir: resumeOutputDir,
				Artifacts: runresult.ScanArtifacts{
					JournalPath: resumeJournalPath,
				},
			}
			tracker, err := startResultTracker(cmd, runresult.CommandResume, resumeResultFile, func(r *runresult.Result) {
				cp := scanSec
				r.Scan = &cp
			})
			if err != nil {
				return err
			}
			fail := func(runErr error) error {
				return finishTracker(tracker, cmd.Context().Err(), runErr, func(r *runresult.Result) {
					cp := scanSec
					r.Scan = &cp
				})
			}

			if strings.TrimSpace(resumeJournalPath) == "" {
				return fail(fmt.Errorf("--journal is required"))
			}
			if err := prepare(cmd, args); err != nil {
				return fail(err)
			}
			scanSec.Scope = effectiveConfig.Scope
			scanSec.VantageKey = effectiveConfig.VantageKey
			scanSec.Profile = effectiveConfig.Scan.Profile
			scanSec.GraphMode = effectiveConfig.Scan.GraphMode
			scanSec.ContentMode = effectiveContentMode(effectiveConfig)

			var scanOpts []scanner.Option
			scanOpts = append(scanOpts, scanner.WithCollectorVersion(version))
			if resumeDiscoveryFile != "" {
				defs, err := discovery.LoadDefinitionsFile(resumeDiscoveryFile)
				if err != nil {
					return fail(fmt.Errorf("load discovery definitions: %w", err))
				}
				scanOpts = append(scanOpts, scanner.WithDefinitions(defs))
			}
			if len(preparedEndpoints) > 0 {
				scanOpts = append(scanOpts, scanner.WithEndpoints(preparedEndpoints))
			}
			if tracker != nil {
				scanOpts = append(scanOpts, scanner.WithOnStart(func(st scanner.ScanStart) error {
					if err := checkScanResultCollisions(resumeResultFile, st.OutputDir, st.Prefix, st.JournalPath); err != nil {
						return err
					}
					tc := st.TargetsCount
					scanSec.ScanID = st.ScanID
					scanSec.Prefix = st.Prefix
					scanSec.OutputDir = st.OutputDir
					scanSec.TargetsCount = &tc
					scanSec.Artifacts.JournalPath = st.JournalPath
					return tracker.UpdatePending(func(r *runresult.Result) {
						cp := scanSec
						r.Scan = &cp
					})
				}))
			}
			s, err := scanner.New(effectiveConfig, withProgress(cmd, scanOpts)...)
			if err != nil {
				return fail(err)
			}
			res, err := s.Resume(cmd.Context(), resumeJournalPath, prepared, resumeOutputDir, resumePrefix)
			if res != nil {
				populateScanSection(&scanSec, res)
			}
			if err != nil {
				scanSec.Resumable = journalExists(scanSec.Artifacts.JournalPath)
				return fail(err)
			}
			if sumErr := printScanSummary(cmd, "Resume", res); sumErr != nil {
				scanSec.Resumable = journalExists(scanSec.Artifacts.JournalPath)
				return fail(sumErr)
			}
			scanSec.Resumable = false
			return finishTracker(tracker, cmd.Context().Err(), nil, func(r *runresult.Result) {
				cp := scanSec
				r.Scan = &cp
			})
		},
	}
	resumeCmd.Flags().StringVar(&resumeJournalPath, "journal", "", "Path to existing .journal.jsonl file (required)")
	resumeCmd.Flags().StringVar(&resumeOutputDir, "output-dir", "", "Directory to write resumed scan artifacts (default: journal directory)")
	resumeCmd.Flags().StringVar(&resumePrefix, "prefix", "", "Filename prefix for resumed artifacts (default: derived from journal filename)")
	resumeCmd.Flags().StringVar(&resumeDiscoveryFile, "discovery-file", "", "Optional custom discovery fingerprint definitions file")
	resumeCmd.Flags().DurationVar(&progressInterval, "progress-interval", 30*time.Second, "Print a progress line to stderr at this interval (0 disables)")
	resumeCmd.Flags().StringVar(&resumeResultFile, "result-file", "", "Optional path to write a machine-readable JSON lifecycle result file")
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
		noZIP             bool
		chunkSize         int
		uploadResultFile  string
	)

	uploadCmd := &cobra.Command{
		Use:   "upload",
		Short: "Validate BloodHound CE adapter, register schema, upload OpenGraph payloads, and import saved queries",
		Long:  "Runs the M3 BloodHound CE validation gate, registers the LLMHound extension schema,\nperforms M0 Q5 two-step upload (with read-only Cypher existence pre-flight for linking\npayloads), and imports saved searches into BloodHound CE.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkUploadResultCollisions(uploadResultFile, baseFile, linkingFile); err != nil {
				return err
			}
			warnSecretFlags(cmd, map[string]string{
				"token-key": "BLOODHOUND_TOKEN_KEY", "bearer-token": "BLOODHOUND_BEARER_TOKEN", "password": "BLOODHOUND_PASSWORD",
			})
			resolvedURL := firstNonEmpty(bhURL, os.Getenv("BLOODHOUND_URL"))
			uploadSec := runresult.UploadSection{
				URL:                 runresult.SanitizeURL(resolvedURL),
				ValidateOnly:        validateOnly,
				RegisterSchema:      registerSchema,
				EnableRulesSchema:   enableRulesSchema,
				ImportQueries:       importQueries,
				IncludeCanExecuteOn: includeCanExec,
				AllowUnvalidatedCE:  allowUnvalidated,
				BaseFile:            baseFile,
				LinkingFile:         linkingFile,
				QueriesDir:          queriesDir,
			}
			tracker, err := startResultTracker(cmd, runresult.CommandUpload, uploadResultFile, func(r *runresult.Result) {
				cp := uploadSec
				r.Upload = &cp
			})
			if err != nil {
				return err
			}
			fail := func(runErr error) error {
				return finishTracker(tracker, cmd.Context().Err(), runErr, func(r *runresult.Result) {
					cp := uploadSec
					r.Upload = &cp
				})
			}

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
				return fail(err)
			}
			defer client.CloseIdleConnections()

			if !validateOnly && !registerSchema && baseFile == "" && linkingFile == "" && !importQueries {
				return fail(fmt.Errorf("nothing to do: specify at least one of --validate-only, --register-schema, --base-file, --linking-file, or --import-queries"))
			}

			ctx := cmd.Context()
			gate, err := client.ValidateAdapter(ctx, allowUnvalidated)
			uploadSec.Gate = gate
			if err != nil {
				return fail(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "BloodHound CE %s (%s) adapter gate passed\n", gate.ServerVersion, gate.Edition)
			for _, chk := range gate.Checks {
				if chk.Warning != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  WARNING [%s]: %s\n", chk.Name, chk.Warning)
				}
			}

			if validateOnly {
				return finishTracker(tracker, ctx.Err(), nil, func(r *runresult.Result) {
					cp := uploadSec
					r.Upload = &cp
				})
			}

			if registerSchema {
				schemaBytes := extension.SchemaJSON
				if enableRulesSchema {
					schemaBytes, err = rules.SchemaWithCanExecuteOn(schemaBytes)
					if err != nil {
						return fail(fmt.Errorf("build rules schema extension: %w", err))
					}
				}
				if err := client.RegisterExtension(ctx, schemaBytes); err != nil {
					return fail(fmt.Errorf("register extension schema: %w", err))
				}
				uploadSec.SchemaRegistered = true
				fmt.Fprintf(cmd.OutOrStdout(), "Extension schema registered (rules_schema=%v)\n", enableRulesSchema)
			}

			if baseFile != "" || linkingFile != "" {
				var opts bloodhound.UploadOptions
				opts.PollInterval = pollInterval
				opts.PollTimeout = uploadTimeout
				opts.MaxRetries = maxRetries
				opts.DisableZIP = noZIP
				opts.MaxChunkItems = chunkSize
				if baseFile != "" {
					b, err := os.ReadFile(baseFile)
					if err != nil {
						return fail(fmt.Errorf("read base file %q: %w", baseFile, err))
					}
					opts.BasePayloadBytes = b
					opts.BaseFileName = filepath.Base(baseFile)
				}
				if linkingFile != "" {
					b, err := os.ReadFile(linkingFile)
					if err != nil {
						return fail(fmt.Errorf("read linking file %q: %w", linkingFile, err))
					}
					opts.LinkingPayloadBytes = b
					opts.LinkingFileName = filepath.Base(linkingFile)
				}
				rep, err := client.UploadScan(ctx, opts)
				if rep != nil {
					runresult.ApplyUploadReport(&uploadSec, rep)
				}
				if err != nil {
					return fail(err)
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
						return fail(err)
					}
				} else {
					kinds, err := client.TraversablePathKinds(ctx, includeCanExec)
					if err != nil {
						return fail(fmt.Errorf("discover traversable path kinds: %w", err))
					}
					if len(kinds) == 0 {
						return fail(fmt.Errorf("no traversable path kinds reported by BloodHound CE; pass --queries-dir or register extension edges first"))
					}
					queries = savedsearch.GenerateWithOptions(kinds, savedsearch.GenerateOptions{
						IncludeCanExecuteOn: includeCanExec,
					})
				}
				n, err := client.ImportSavedQueries(ctx, queries)
				if err != nil {
					return fail(fmt.Errorf("import saved queries: %w", err))
				}
				uploadSec.QueriesImported = n
				fmt.Fprintf(cmd.OutOrStdout(), "  Imported %d saved queries into BloodHound CE\n", n)
			}

			return finishTracker(tracker, ctx.Err(), nil, func(r *runresult.Result) {
				cp := uploadSec
				r.Upload = &cp
			})
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
	uploadCmd.Flags().BoolVar(&noZIP, "no-zip", false, "Upload raw uncompressed JSON instead of application/zip")
	uploadCmd.Flags().IntVar(&chunkSize, "chunk-size", bloodhound.DefaultMaxChunkItems, "Maximum nodes+edges per BloodHound upload job")
	uploadCmd.Flags().StringVar(&uploadResultFile, "result-file", "", "Optional path to write a machine-readable JSON lifecycle result file")
	root.AddCommand(uploadCmd)
	return root
}

type bhSeedOptions struct {
	enabled     bool
	url         string
	tokenID     string
	tokenKey    string
	bearerToken string
	username    string
	password    string
	hops        int
	insecure    bool
}

func bindBHSeedFlags(cmd *cobra.Command, opts *bhSeedOptions) {
	f := cmd.Flags()
	f.BoolVar(&opts.enabled, "prioritize-from-bh", false, "Query BloodHound CE read-only for Tier-0-adjacent hosts and scan them first")
	f.StringVar(&opts.url, "bh-url", "", "BloodHound CE base URL (or BLOODHOUND_URL) for --prioritize-from-bh")
	f.StringVar(&opts.tokenID, "bh-token-id", "", "BloodHound HMAC Token ID (or BLOODHOUND_TOKEN_ID)")
	f.StringVar(&opts.tokenKey, "bh-token-key", "", "BloodHound HMAC Token Key (or BLOODHOUND_TOKEN_KEY)")
	f.StringVar(&opts.bearerToken, "bh-bearer-token", "", "BloodHound Bearer JWT (or BLOODHOUND_BEARER_TOKEN)")
	f.StringVar(&opts.username, "bh-username", "", "BloodHound username (or BLOODHOUND_USERNAME)")
	f.StringVar(&opts.password, "bh-password", "", "BloodHound password (or BLOODHOUND_PASSWORD)")
	f.IntVar(&opts.hops, "bh-hops", 2, "Traversable hops from Tag_Tier_Zero for --prioritize-from-bh (1–3)")
	f.BoolVar(&opts.insecure, "bh-insecure", false, "Bypass TLS verification for BloodHound CE seed lookup")
}

func fetchTier0PriorityIDs(cmd *cobra.Command, opts bhSeedOptions) (map[string]bool, error) {
	warnSecretFlags(cmd, map[string]string{
		"bh-token-key": "BLOODHOUND_TOKEN_KEY", "bh-bearer-token": "BLOODHOUND_BEARER_TOKEN", "bh-password": "BLOODHOUND_PASSWORD",
	})
	resolvedURL := firstNonEmpty(opts.url, os.Getenv("BLOODHOUND_URL"))
	auth := bloodhound.AuthConfig{
		TokenID:     firstNonEmpty(opts.tokenID, os.Getenv("BLOODHOUND_TOKEN_ID")),
		TokenKey:    firstNonEmpty(opts.tokenKey, os.Getenv("BLOODHOUND_TOKEN_KEY")),
		BearerToken: firstNonEmpty(opts.bearerToken, os.Getenv("BLOODHOUND_BEARER_TOKEN")),
		Username:    firstNonEmpty(opts.username, os.Getenv("BLOODHOUND_USERNAME")),
		Password:    firstNonEmpty(opts.password, os.Getenv("BLOODHOUND_PASSWORD")),
	}
	client, err := bloodhound.NewClient(bloodhound.ClientConfig{
		BaseURL:   resolvedURL,
		Auth:      auth,
		Timeout:   30 * time.Second,
		Insecure:  opts.insecure,
		UserAgent: "LLMHound/" + version,
	})
	if err != nil {
		return nil, fmt.Errorf("bloodhound priority lookup: %w", err)
	}
	ids, capped, err := client.Tier0AdjacentObjectIDsWithCap(cmd.Context(), opts.hops, bloodhound.CEResultCap)
	if err != nil {
		return nil, err
	}
	if capped {
		fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: a Tier-0 seed query reached BloodHound CE's ~%d-node result cap; only part of the Tier-0-adjacent set is prioritized (every target is still scanned).\n", bloodhound.CEResultCap)
	}
	return ids, nil
}

// printScanSummary reports the artifacts written and returns an error (non-zero
// exit) when any target failed with a collection error, after the artifacts
// for every other target were still emitted.
func printScanSummary(cmd *cobra.Command, verb string, res *scanner.ScanResult) error {
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
	if res.TargetErrorCount == 0 {
		return nil
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%d target(s) failed with collection errors (journaled as failed; `llmhound resume --journal %s` retries them):\n", res.TargetErrorCount, res.JournalPath)
	for _, e := range res.TargetErrors {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s\n", e)
	}
	if extra := res.TargetErrorCount - len(res.TargetErrors); extra > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "  ... and %d more (see the journal)\n", extra)
	}
	return fmt.Errorf("%s finished with %d target error(s); all other artifacts were written", strings.ToLower(verb), res.TargetErrorCount)
}

// warnSecretFlags warns when a credential was passed as a command-line flag:
// arguments are visible to other users in process listings and are kept in
// shell history and (on Windows) task scheduler definitions. The environment
// variable equivalent is preferred.
func warnSecretFlags(cmd *cobra.Command, flagToEnv map[string]string) {
	names := make([]string, 0, len(flagToEnv))
	for name := range flagToEnv {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: --%s exposes a credential in process listings and shell history; set %s instead.\n", name, flagToEnv[name])
		}
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
