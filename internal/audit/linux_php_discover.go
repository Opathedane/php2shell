package audit

// linuxWellKnownPHPGlobs returns bounded, non-recursive search patterns for common
// Linux PHP layouts (distribution, Plesk, Remi SCL, cPanel EasyApache, /usr/local).
// Operators needing arbitrary trees should use --deep-root (v2.6.0+), not broader globs.
func linuxWellKnownPHPGlobs() []string {
	return []string{
		`/usr/bin/php*`,
		`/usr/sbin/php-fpm*`,
		`/usr/local/bin/php*`,
		`/usr/local/sbin/php-fpm*`,
		`/usr/local/php*/bin/php*`,
		`/usr/local/php*/sbin/php-fpm*`,
		`/opt/plesk/php/*/bin/php*`,
		`/opt/plesk/php/*/sbin/php-fpm*`,
		`/opt/remi/php*/root/usr/bin/php*`,
		`/opt/remi/php*/root/usr/sbin/php-fpm*`,
		`/opt/cpanel/ea-php*/root/usr/bin/php*`,
		`/opt/cpanel/ea-php*/root/usr/sbin/php-fpm*`,
		`/opt/php/*/bin/php*`,
		`/opt/php/*/sbin/php-fpm*`,
		`/etc/alternatives/php`,
	}
}
