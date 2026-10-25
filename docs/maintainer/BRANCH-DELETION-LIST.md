# Remote branch deletion list (approval required)

**Do not delete until explicit GO.** Generated after PR #38 merge into `main`.

## Excluded (never delete via this list)

- `main`
- All release tags (`v2.3.0` … `v2.8.0`, alphas)
- Any branch with `ahead > 0` vs `origin/main` (none found at generation time)

## Safe to delete (fully contained in `main`, ahead=0)

| Branch | Tip | Behind main | Associated merged PR(s) |
| --- | --- | ---: | --- |
| `ci/node24-actions` | `6519864` | 9 | #36 |
| `docs/post-2.3.0-quality` | `e8f9608` | 109 | #4 |
| `docs/v2.5.1-post-release-hardening` | `0d868aa` | 96 | (no merged PR linked / likely squash-or-direct) |
| `feat/compromise-investigation` | `bd3c58d` | 86 | #13 |
| `feat/csv-fleet-reporting-2.4.0` | `03abb30` | 103 | #7 |
| `feat/deep-discovery-2.6.0` | `354f316` | 92 | #10 |
| `feat/enterprise-production-readiness` | `0cb80bc` | 66 | #21 |
| `feat/html-report-cli` | `2f74418` | 116 | #2 |
| `feat/nginx-fpm-discovery` | `1cfeb78` | 18 | #34 |
| `feat/offline-edr-investigation` | `f6a172c` | 84 | #14 |
| `feat/php-discovery-2.5.0` | `3df568b` | 100 | #8 |
| `feat/runtime-detection` | `aac562d` | 118 | #1 |
| `feat/simplified-html-report` | `707b97a` | 111 | #3 |
| `feat/v2.7.1-ir-accuracy` | `5aed46c` | 72 | #18 |
| `feat/v2.7.1-waf-cloudflare` | `f1f3d31` | 70 | #19 |
| `feat/v2.7.2-cve-115560-session-upload` | `38b342a` | 57 | #24 |
| `feat/webroot-compromise-investigation` | `3bf40d6` | 79 | #15 |
| `feat/wellknown-discovery-2.7.0` | `6ff40ee` | 90 | #11 |
| `feat/windows-2012r2-legacy` | `3d6bdb3` | 68 | #20 |
| `fix/php-ini-visibility-operator-paths` | `6275e5d` | 97 | #9 |
| `fix/unix-php-symlink-discovery` | `782e01f` | 26 | #32 |
| `fix/v2.7.3-no-php-reporting` | `fc24d67` | 38 | #28 |
| `fix/windows-php-version-inference-2.3.1` | `5382940` | 107 | #5 |
| `release/prepare-2.3.1` | `082be8d` | 105 | #6 |
| `release/prepare-2.6.0` | `0bbd83c` | 88 | #12 |
| `release/prepare-2.7.0` | `f2ab626` | 77 | #16 |
| `release/publish-2.7.0` | `9108d0d` | 75 | #17 |
| `release/publish-2.7.1` | `c7c6595` | 61 | #22 |
| `release/v2.7.3-finalize` | `f80e2cb` | 35 | #29 |
| `release/v2.7.5-prep` | `e22b092` | 22 | #33 |
| `release/v2.8.0-prep` | `d95d00f` | 5 | #37 |
| `stab/v2.7.2-enterprise-qa` | `20f882e` | 44 | #27, #26, #25 |
| `validate/nginx-fpm-v2.8.0-readiness` | `e7b4a83` | 11 | #35 |

## Counts

- Safe delete: 33
- Excluded / unsafe: 0

## Exact git commands (do not run without GO)

```bash
git push origin --delete ci/node24-actions
git push origin --delete docs/post-2.3.0-quality
git push origin --delete docs/v2.5.1-post-release-hardening
git push origin --delete feat/compromise-investigation
git push origin --delete feat/csv-fleet-reporting-2.4.0
git push origin --delete feat/deep-discovery-2.6.0
git push origin --delete feat/enterprise-production-readiness
git push origin --delete feat/html-report-cli
git push origin --delete feat/nginx-fpm-discovery
git push origin --delete feat/offline-edr-investigation
git push origin --delete feat/php-discovery-2.5.0
git push origin --delete feat/runtime-detection
git push origin --delete feat/simplified-html-report
git push origin --delete feat/v2.7.1-ir-accuracy
git push origin --delete feat/v2.7.1-waf-cloudflare
git push origin --delete feat/v2.7.2-cve-115560-session-upload
git push origin --delete feat/webroot-compromise-investigation
git push origin --delete feat/wellknown-discovery-2.7.0
git push origin --delete feat/windows-2012r2-legacy
git push origin --delete fix/php-ini-visibility-operator-paths
git push origin --delete fix/unix-php-symlink-discovery
git push origin --delete fix/v2.7.3-no-php-reporting
git push origin --delete fix/windows-php-version-inference-2.3.1
git push origin --delete release/prepare-2.3.1
git push origin --delete release/prepare-2.6.0
git push origin --delete release/prepare-2.7.0
git push origin --delete release/publish-2.7.0
git push origin --delete release/publish-2.7.1
git push origin --delete release/v2.7.3-finalize
git push origin --delete release/v2.7.5-prep
git push origin --delete release/v2.8.0-prep
git push origin --delete stab/v2.7.2-enterprise-qa
git push origin --delete validate/nginx-fpm-v2.8.0-readiness
```
