package audit

// HostScanOptions controls optional bounded host inventory beyond the default scan.
// All paths are operator-authorized; the scanner never invents drive-wide roots.
type HostScanOptions struct {
	Webroot string
	Docker  bool
	// PHPIniPaths are explicit php.ini (or .ini) files from --php-ini (repeatable).
	PHPIniPaths []string
	// ConfigRoots are directories from --config-root (repeatable): bounded PHP binary
	// discovery plus common php.ini names and a single conf.d/*.ini layer (no drive walk).
	ConfigRoots []string
	// DeepRoots are directories from --deep-root (repeatable, off by default): recursive
	// bounded discovery of PHP binaries and php.ini-like files under authorized roots only.
	DeepRoots []string
}

const (
	maxOperatorPHPIniPaths = 32
	maxOperatorConfigRoots = 8
	maxConfigRootIniFiles  = 64
)
