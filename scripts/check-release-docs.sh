#!/usr/bin/env bash
# Pre-publication / CI checks for version consistency and stale release wording.
# Usage:
#   scripts/check-release-docs.sh                 # verify tree for embedded Version
#   scripts/check-release-docs.sh --for-tag vX.Y.Z  # strict checks before gh release create
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(sed -n 's/^const Version = "\([^"]*\)"/\1/p' internal/audit/model.go | head -1)"
if [[ -z "$VERSION" ]]; then
  echo "error: could not read Version from internal/audit/model.go" >&2
  exit 1
fi

EXPECT_TAG=""
if [[ "${1:-}" == "--for-tag" ]]; then
  EXPECT_TAG="${2:-}"
  if [[ -z "$EXPECT_TAG" || ! "$EXPECT_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: --for-tag requires vX.Y.Z" >&2
    exit 1
  fi
  if [[ "$EXPECT_TAG" != "v${VERSION}" ]]; then
    echo "error: tag $EXPECT_TAG does not match model.go Version v${VERSION}" >&2
    exit 1
  fi
fi

fail=0
err() { echo "error: $*" >&2; fail=1; }

NOTES_FILE="docs/releases/v${VERSION}.md"
if [[ ! -f "$NOTES_FILE" ]]; then
  err "missing version-specific release notes: $NOTES_FILE"
else
  if grep -Eiq 'unreleased draft|do not tag or publish until|latest public release remains' "$NOTES_FILE"; then
    err "$NOTES_FILE contains draft/stale language unsuitable for a GitHub Release body"
  fi
  if ! grep -Eq "^# PHP2Shell v${VERSION}([[:space:]]|$)" "$NOTES_FILE"; then
    err "$NOTES_FILE should start with heading '# PHP2Shell v${VERSION}'"
  fi
fi

if grep -Eiq "Version in this tree:[[:space:]]*${VERSION}[[:space:]]*\([^)]*unreleased" README.md; then
  err "README.md still describes ${VERSION} as unreleased"
fi
if ! grep -Eiq "Latest public release:.*v${VERSION}" README.md; then
  err "README.md should identify v${VERSION} as the latest public release"
fi

# Unreleased heading must not target the already-shipped Version (awk avoids grep -A bleed).
# Exit status 0 from awk means a problem was found.
if awk -v ver="$VERSION" '
  BEGIN { in_unrel=0; bad=0 }
  /^## Unreleased/ {
    in_unrel=1
    if (index($0, "toward v" ver) || index($0, "(v" ver ")") ) bad=1
    next
  }
  /^## / { in_unrel=0 }
  in_unrel && index($0, "toward v" ver) { bad=1 }
  END { exit bad ? 0 : 1 }
' CHANGELOG.md; then
  err "CHANGELOG.md Unreleased section still targets shipped v${VERSION}"
fi

if ! grep -Eq "^## v${VERSION} — " CHANGELOG.md; then
  err "CHANGELOG.md missing finalized heading '## v${VERSION} — YYYY-MM-DD'"
fi

for f in docs/INSTALL-FOR-CONSULTANTS.md docs/ADVANCED-USAGE.md; do
  if grep -Eiq "unreleased[[:space:]]+${VERSION}|unreleased[[:space:]]+\*\*${VERSION}\*\*|Tree may include unreleased \*\*${VERSION}\*\*" "$f"; then
    err "$f still describes ${VERSION} as unreleased"
  fi
  if ! grep -Eiq "Latest public release:.*v${VERSION}" "$f"; then
    err "$f should identify v${VERSION} as the latest public release"
  fi
done

if head -12 docs/RELEASE-NOTES.md | grep -Eiq 'unreleased draft|do not tag or publish until'; then
  err "docs/RELEASE-NOTES.md still opens as an unreleased draft"
fi
if ! grep -Eq "Latest public release:.*\[v${VERSION}\]" docs/RELEASE-NOTES.md; then
  err "docs/RELEASE-NOTES.md should list v${VERSION} as latest public release"
fi
if ! grep -Eq "releases/v${VERSION}\.md" docs/RELEASE-NOTES.md; then
  err "docs/RELEASE-NOTES.md index should link docs/releases/v${VERSION}.md"
fi

# Workflow must not publish the historical index as the release body.
if grep -Eq -- '--notes-file docs/RELEASE-NOTES\.md' .github/workflows/release.yml; then
  err "release.yml must not use --notes-file docs/RELEASE-NOTES.md (use docs/releases/\${TAG}.md)"
fi
if grep -Eq "default: v2\.4\.0" .github/workflows/release.yml; then
  err "release.yml workflow_dispatch default still hard-codes v2.4.0"
fi

if [[ -n "$EXPECT_TAG" ]]; then
  TAG_NOTES="docs/releases/${EXPECT_TAG}.md"
  if [[ ! -f "$TAG_NOTES" ]]; then
    err "missing notes file for publish: $TAG_NOTES"
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo "check-release-docs: FAILED (Version=${VERSION})" >&2
  exit 1
fi
echo "check-release-docs: OK (Version=${VERSION}${EXPECT_TAG:+, tag=$EXPECT_TAG})"
