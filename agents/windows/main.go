// SBOMGuard Windows agent — enumerates installed software from the registry,
// generates a CycloneDX 1.4 SBOM, and uploads it to the SBOMGuard server.
//
// Usage:
//
//	sbom_agent.exe [flags]
//	  -server URL   Upload URL (default http://10.10.0.40:8082/api/sbom)
//	  -output FILE  Write SBOM JSON to file instead of uploading
//	  -install      Register weekly Windows Scheduled Task (requires admin)
//	  -uninstall    Remove scheduled task (requires admin)
//	  -dry-run      Print SBOM JSON to stdout, do not upload
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	agentVersion = "1.0"
	defaultURL   = "http://10.10.0.40:8082/api/sbom/import"
)

// ── CycloneDX 1.4 types ───────────────────────────────────────────────────────

type SBOM struct {
	BomFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []Tool    `json:"tools"`
	Component Component `json:"component"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Component struct {
	Type       string     `json:"type"`
	BomRef     string     `json:"bom-ref,omitempty"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	Publisher  string     `json:"publisher,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ── Registry enumeration ──────────────────────────────────────────────────────

type softwareEntry struct {
	Name      string
	Version   string
	Publisher string
	Source    string
}

func readUninstallKey(root registry.Key, path, source string) []softwareEntry {
	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.READ)
	if err != nil {
		return nil
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	var entries []softwareEntry
	for _, name := range names {
		sub, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		displayName, _, _ := sub.GetStringValue("DisplayName")
		displayVersion, _, _ := sub.GetStringValue("DisplayVersion")
		publisher, _, _ := sub.GetStringValue("Publisher")
		sub.Close()

		if displayName == "" {
			continue
		}
		entries = append(entries, softwareEntry{
			Name:      displayName,
			Version:   displayVersion,
			Publisher: publisher,
			Source:    source,
		})
	}
	return entries
}

func collectSoftware() []softwareEntry {
	type src struct {
		root   registry.Key
		path   string
		source string
	}
	sources := []src{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "HKLM64"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "HKLM32"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "HKCU"},
	}

	var all []softwareEntry
	seen := make(map[string]bool)
	for _, s := range sources {
		for _, e := range readUninstallKey(s.root, s.path, s.source) {
			key := strings.ToLower(e.Name + "|" + e.Version)
			if !seen[key] {
				seen[key] = true
				all = append(all, e)
			}
		}
	}
	return all
}

// ── Windows OS version ────────────────────────────────────────────────────────

func windowsVersion() string {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "Windows"
	}
	defer key.Close()

	product, _, _ := key.GetStringValue("ProductName")
	build, _, _ := key.GetStringValue("CurrentBuildNumber")
	display, _, _ := key.GetStringValue("DisplayVersion")

	switch {
	case product != "" && display != "" && build != "":
		return fmt.Sprintf("%s %s (build %s)", product, display, build)
	case product != "" && build != "":
		return fmt.Sprintf("%s (build %s)", product, build)
	case product != "":
		return product
	default:
		return "Windows"
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// newUUID returns a UUID v4 formatted as urn:uuid:...
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// safePURLSegment replaces characters invalid in a PURL segment with '-'.
func safePURLSegment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

func makePURL(name, version, publisher string) string {
	n := safePURLSegment(name)
	v := version
	if v == "" {
		v = "unknown"
	}
	v = strings.ReplaceAll(v, " ", "-")
	if publisher != "" {
		p := safePURLSegment(publisher)
		return fmt.Sprintf("pkg:generic/%s/%s@%s", p, n, v)
	}
	return fmt.Sprintf("pkg:generic/%s@%s", n, v)
}

// ── SBOM assembly ─────────────────────────────────────────────────────────────

func buildSBOM() *SBOM {
	host := hostname()
	osVer := windowsVersion()
	software := collectSoftware()

	components := make([]Component, 0, len(software))
	for _, sw := range software {
		purl := makePURL(sw.Name, sw.Version, sw.Publisher)
		components = append(components, Component{
			Type:      "library",
			BomRef:    purl,
			Name:      sw.Name,
			Version:   sw.Version,
			Publisher: sw.Publisher,
			PURL:      purl,
			Properties: []Property{
				{Name: "registry_source", Value: sw.Source},
			},
		})
	}

	return &SBOM{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.4",
		SerialNumber: newUUID(),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools:     []Tool{{Vendor: "SBOMGuard", Name: "windows-agent", Version: agentVersion}},
			Component: Component{
				Type:   "operating-system",
				BomRef: "host",
				Name:   host,
				Version: osVer,
				Properties: []Property{
					{Name: "arch", Value: runtime.GOARCH},
				},
			},
		},
		Components: components,
	}
}

// ── Upload ────────────────────────────────────────────────────────────────────

func upload(sbom *SBOM, serverURL string) error {
	payload := map[string]interface{}{
		"host": sbom.Metadata.Component.Name,
		"sbom": sbom,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest("POST", serverURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sbomguard-windows-agent/"+agentVersion)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// ── Scheduled Task ────────────────────────────────────────────────────────────

func installTask(serverURL string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Weekly, Sunday 02:00, run as SYSTEM
	args := []string{
		"/create", "/tn", "SBOMGuard",
		"/tr", fmt.Sprintf(`"%s" -server %s`, exe, serverURL),
		"/sc", "WEEKLY", "/d", "SUN", "/st", "02:00",
		"/ru", "SYSTEM", "/f",
	}
	out, err := exec.Command("schtasks", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks: %v\n%s", err, out)
	}
	fmt.Printf("Scheduled task created (Sun 02:00, SYSTEM)\n%s\n", strings.TrimSpace(string(out)))
	return nil
}

func uninstallTask() error {
	out, err := exec.Command("schtasks", "/delete", "/tn", "SBOMGuard", "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks: %v\n%s", err, out)
	}
	fmt.Printf("Scheduled task removed\n%s\n", strings.TrimSpace(string(out)))
	return nil
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	serverURL := defaultURL
	outputFile := ""
	install := false
	uninstall := false
	dryRun := false

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-server":
			i++
			if i < len(args) {
				serverURL = args[i]
			}
		case "-output":
			i++
			if i < len(args) {
				outputFile = args[i]
			}
		case "-install":
			install = true
		case "-uninstall":
			uninstall = true
		case "-dry-run":
			dryRun = true
		case "-help", "--help", "-h":
			fmt.Fprintf(os.Stderr, "SBOMGuard Windows Agent v%s\n\nFlags:\n"+
				"  -server URL    Upload URL (default: %s)\n"+
				"  -output FILE   Write SBOM to file instead of uploading\n"+
				"  -install       Register weekly Scheduled Task (admin required)\n"+
				"  -uninstall     Remove scheduled task (admin required)\n"+
				"  -dry-run       Print SBOM JSON to stdout\n", agentVersion, defaultURL)
			return
		}
	}

	if install {
		if err := installTask(serverURL); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
		return
	}
	if uninstall {
		if err := uninstallTask(); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
		return
	}

	fmt.Printf("Generating SBOM for %s ...\n", hostname())
	sbom := buildSBOM()
	fmt.Printf("Found %d installed packages\n", len(sbom.Components))

	if dryRun {
		data, _ := json.MarshalIndent(sbom, "", "  ")
		fmt.Println(string(data))
		return
	}

	if outputFile != "" {
		data, _ := json.MarshalIndent(sbom, "", "  ")
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
		fmt.Printf("Written to %s\n", outputFile)
		return
	}

	fmt.Printf("Uploading to %s ...\n", serverURL)
	if err := upload(sbom, serverURL); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	fmt.Println("Done.")
}
