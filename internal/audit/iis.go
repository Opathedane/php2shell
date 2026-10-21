package audit

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// IIS PHP handler configuration is static evidence. It does NOT attest that the
// worker process serving a given URL uses the handler or runs a patched runtime.
func parseIISHandlers(path string, data []byte) ([]Evidence, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	result := []Evidence{}
	for {
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		el, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		name := strings.ToLower(el.Name.Local)
		if name != "add" && name != "application" {
			continue
		}
		attrs := map[string]string{}
		for _, a := range el.Attr {
			attrs[strings.ToLower(a.Name.Local)] = a.Value
		}
		module := strings.ToLower(attrs["modules"])
		exec := attrs["scriptprocessor"]
		if exec == "" {
			exec = attrs["fullpath"]
		}
		if (strings.Contains(module, "fastcgi") && strings.Contains(strings.ToLower(attrs["path"]), "php")) || strings.Contains(strings.ToLower(exec), "php") || strings.Contains(strings.ToLower(attrs["path"]), "*.php") {
			result = append(result, Evidence{Type: "iis_php_handler_config", Name: attrs["name"], Source: "IIS applicationHost.config (static XML)", Location: path, Detail: FormatIISHandlerDetail(attrs["path"], attrs["modules"], exec), Interpretation: "CONFIGURED_HANDLER_NOT_VERIFIED_SERVING_RUNTIME"})
			if len(result) >= 128 {
				break
			}
		}
	}
	return result, nil
}
