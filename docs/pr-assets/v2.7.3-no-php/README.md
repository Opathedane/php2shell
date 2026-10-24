# v2.7.3 no-PHP reporting — PR preview assets

Synthetic HTML (no customer data) used for Draft PR visual review.

| File | Meaning |
| --- | --- |
| `before-04-no-php-detected.html` / `before-no-php.png` | v2.7.2 example: empty host mislabeled as inventory incomplete |
| `after-04-no-php-detected.html` / `after-no-php.png` | v2.7.3: Windows complete coverage → no PHP within scan coverage |
| `after-windows-incomplete.html` / `after-windows-incomplete.png` | v2.7.3: genuine Windows discovery failures remain visible |

Registry is not a separate discovery source in this release; Windows coverage uses PATH/filesystem (`binary_paths`), processes, IIS configuration, and optional deep/config roots.
