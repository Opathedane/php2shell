package audit

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FleetRollupOptions controls CSV consolidation for one analyst-selected customer collection.
type FleetRollupOptions struct {
	// InputFiles are explicit fleet CSV paths.
	InputFiles []string
	// InputDir, when set, loads all *.csv files directly under the directory (non-recursive).
	InputDir string
	// Output is the exclusive consolidated CSV path.
	Output string
	// RequireSameCustomerLabel when true refuses mixing differing non-empty customer_label values.
	// Default behaviour always refuses conflicting non-empty labels.
	AllowEmptyCustomerLabels bool
}

// CollectFleetCSVInputs resolves --input-dir and explicit file arguments.
func CollectFleetCSVInputs(inputDir string, files []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string) error {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" || p == "." {
			return fmt.Errorf("empty CSV path")
		}
		key := normalizeInstallPath(p)
		if seen[key] {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: not a regular file", p)
		}
		seen[key] = true
		out = append(out, p)
		return nil
	}
	if strings.TrimSpace(inputDir) != "" {
		dir := filepath.Clean(inputDir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("input-dir: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(strings.ToLower(name), ".csv") {
				continue
			}
			if err := add(filepath.Join(dir, name)); err != nil {
				return nil, err
			}
		}
	}
	for _, f := range files {
		if err := add(f); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no fleet CSV inputs found; supply --input-dir DIR and/or CSV file paths")
	}
	if len(out) > 1000 {
		return nil, fmt.Errorf("maximum 1000 CSV inputs")
	}
	return out, nil
}

// RollupFleetCSV merges PHP2Shell fleet CSV reports into one customer-wide CSV.
// The operator selects the input set (directory or file list); customer_label is never
// treated as authenticated tenancy. Conflicting non-empty customer labels are rejected.
func RollupFleetCSV(opts FleetRollupOptions) error {
	files, err := CollectFleetCSVInputs(opts.InputDir, opts.InputFiles)
	if err != nil {
		return err
	}
	if strings.TrimSpace(opts.Output) == "" {
		return fmt.Errorf("rollup --out PATH is required")
	}
	outPath := opts.Output
	if !strings.HasSuffix(strings.ToLower(outPath), ".csv") {
		outPath += ".csv"
	}

	var all []FleetRow
	dedupe := map[string]bool{}
	var customerLabel string
	customerSet := false

	for _, path := range files {
		b, err := ReadRegular(path, 8<<20)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		rows, err := ParseFleetCSV(b)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if len(rows) == 0 {
			return fmt.Errorf("%s: contains no data rows", path)
		}
		for _, row := range rows {
			label := strings.TrimSpace(row.CustomerLabel)
			if label != "" {
				if !customerSet {
					customerLabel = label
					customerSet = true
				} else if label != customerLabel {
					return fmt.Errorf("%s: customer_label %q conflicts with %q; consolidate one customer collection at a time (labels are not authenticated tenancy)", path, label, customerLabel)
				}
			} else if !opts.AllowEmptyCustomerLabels && customerSet && customerLabel != "" {
				// Empty labels may mix with a named collection only when explicitly allowed.
				// Default: allow empty alongside a single non-empty label (common for unattended scans).
			}
			key := row.ScanID + "\x00" + row.InstallID + "\x00" + row.Hostname + "\x00" + row.ScanTimestampUTC + "\x00" + row.InstallPath
			if dedupe[key] {
				continue
			}
			dedupe[key] = true
			all = append(all, row)
		}
	}

	var buf bytes.Buffer
	buf.Write([]byte{0xEF, 0xBB, 0xBF})
	w := csv.NewWriter(&buf)
	if err := w.Write(FleetCSVColumns); err != nil {
		return err
	}
	for _, row := range all {
		if err := w.Write(row.csvFields()); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}

	if err := MakeReportDirectory(outPath); err != nil {
		return err
	}
	if _, err := os.Lstat(outPath); err == nil {
		return fmt.Errorf("output exists, refusing overwrite: %s", outPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, werr := f.Write(buf.Bytes())
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(outPath)
		return fmt.Errorf("rollup write failed: %v %v", werr, cerr)
	}
	return nil
}
