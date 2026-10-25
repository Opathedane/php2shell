package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDumpNginxBackendExamplesForReview(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix")
	}
	if os.Getenv("PHP2SHELL_DUMP_NGINX_EXAMPLES") != "1" {
		t.Skip("set PHP2SHELL_DUMP_NGINX_EXAMPLES=1 to print review examples")
	}
	base := t.TempDir()
	dump := func(label, nginxBody string, fpm map[string]string, extra func(*Report)) {
		nr := filepath.Join(base, label, "nginx")
		writeNginxTree(t, nr, map[string]string{"nginx.conf": nginxBody})
		r := NewReport(label, "linux", "amd64")
		if extra != nil {
			extra(r)
		}
		ParseNginxConfigForTest(r, nr)
		if fpm != nil {
			fr := filepath.Join(base, label, "pool.d")
			writeNginxTree(t, fr, fpm)
			ParseFPMPoolsForTest(r, fr)
			CorrelateNginxFPMBackends(r)
		}
		EvaluatePatchPosture(r)
		FinalizeSummary(r)
		rt, detail := humanRuntime(r)
		fmt.Printf("\n======== %s ========\n", label)
		fmt.Printf("VulnerabilityStatus=%s\nEffectiveWebRuntime=%s\nRuntimeLabel=%s\nRuntimeDetail=%s\nPHPDiscovery=%s\n",
			r.VulnerabilityStatus, r.EffectiveWebRuntime, rt, detail, r.Summary.PHPDiscovery)
		for _, c := range r.Coverage {
			if strings.Contains(c.Name, "nginx") || strings.Contains(c.Name, "php_fpm") {
				fmt.Printf("coverage %s=%s :: %s\n", c.Name, c.Status, c.Detail)
			}
		}
		for _, e := range r.Evidence {
			if strings.Contains(e.Type, "nginx") || strings.Contains(e.Type, "php_fpm") {
				fmt.Printf("evidence %s name=%s ver=%q detail=%s\n", e.Type, e.Name, e.Version, e.Detail)
			}
		}
		html := string(EncodeHTML(r))
		fmt.Printf("HTML runtime label present=%v candidates=%v not_verified=%v\n",
			strings.Contains(html, rt) || strings.Contains(html, "Candidates") || strings.Contains(html, "Not verified"),
			strings.Contains(html, "Candidates"), strings.Contains(html, "Not verified"))
	}
	sock := filepath.Join(base, "php.sock")
	dump("LOCAL", "http { server { server_name local.example; location ~ \\.php$ { fastcgi_pass unix:"+sock+"; } } }",
		map[string]string{"www.conf": "[www]\nlisten = " + sock + "\n"}, nil)
	dump("REMOTE", "http { server { server_name remote.example; location ~ \\.php$ { fastcgi_pass 10.9.9.9:9000; } } }",
		nil, func(r *Report) {
			r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php", Version: "8.4.27", Source: "cli", Location: "/usr/bin/php", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION"})
		})
	dump("AMBIGUOUS", `http {
  upstream php_backend { server 10.0.0.5:9000; server 127.0.0.1:9000; }
  server { location ~ \.php$ { fastcgi_pass php_backend; } }
}`, nil, nil)
}
