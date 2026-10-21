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
UNRELEASED=0
if [[ -f "$NOTES_FILE" ]] && grep -Eiq 'unreleased draft|do not tag or publish until' "$NOTES_FILE"; then
  UNRELEASED=1
fi

if [[ ! -f "$NOTES_FILE" ]]; then
  err "missing version-specific release notes: $NOTES_FILE"
elif [[ -n "$EXPECT_TAG" ]]; then
  # Publishing requires finalized notes (no draft language).
  if [[ "$UNRELEASED" -eq 1 ]]; then
    err "$NOTES_FILE contains draft/unreleased language unsuitable for a GitHub Release body"
  fi
  if ! grep -Eq "^# PHP2Shell v${VERSION}([[:space:]]|$)" "$NOTES_FILE"; then
    err "$NOTES_FILE should start with heading '# PHP2Shell v${VERSION}'"
  fi
elif [[ "$UNRELEASED" -eq 1 ]]; then
  # Development tree: Version is not yet the latest public release.
  if ! grep -Eq "^# PHP2Shell v${VERSION}([[:space:]]|$)" "$NOTES_FILE"; then
    err "$NOTES_FILE should start with heading '# PHP2Shell v${VERSION}'"
  fi
  if ! grep -Eiq "Version in this tree:\**[[:space:]]*${VERSION}[[:space:]]*\([^)]*unreleased" README.md; then
    err "README.md should mark ${VERSION} as unreleased while $NOTES_FILE is a draft"
  fi
  if grep -Eiq "Latest public release:\**[[:space:]]*\[[[:space:]]*v${VERSION}\]" README.md; then
    err "README.md must not claim draft v${VERSION} as the latest public release"
  fi
  if ! awk -v ver="$VERSION" '
    BEGIN { in_unrel=0; ok=0 }
    /^## Unreleased/ {
      in_unrel=1
      if (index($0, "toward v" ver)) ok=1
      next
    }
    /^## / { in_unrel=0 }
    in_unrel && index($0, "toward v" ver) { ok=1 }
    END { exit ok ? 0 : 1 }
  ' CHANGELOG.md; then
    err "CHANGELOG.md should have an Unreleased section targeting toward v${VERSION} while notes are draft"
  fi
  if grep -Eq "^## v${VERSION} — " CHANGELOG.md; then
    err "CHANGELOG.md must not finalize ## v${VERSION} — while $NOTES_FILE is still a draft"
  fi
  if head -12 docs/RELEASE-NOTES.md | grep -Eiq 'unreleased draft|do not tag or publish until'; then
    err "docs/RELEASE-NOTES.md still opens as an unreleased draft (keep latest public current; link draft notes from the table only)"
  fi
  if grep -Eq "Latest public release:.*\[v${VERSION}\]" docs/RELEASE-NOTES.md; then
    err "docs/RELEASE-NOTES.md must not list draft v${VERSION} as latest public release"
  fi
  if ! grep -Eq "releases/v${VERSION}\.md" docs/RELEASE-NOTES.md; then
    err "docs/RELEASE-NOTES.md index should link docs/releases/v${VERSION}.md (draft row OK)"
  fi
  for f in docs/INSTALL-FOR-CONSULTANTS.md docs/ADVANCED-USAGE.md; do
    if grep -Eiq "Latest public release:.*v${VERSION}" "$f" && ! grep -Eiq "unreleased|tree may include|development" "$f"; then
      # Allow mentioning vVERSION as in-tree/unreleased; reject claiming it as sole latest public.
      if grep -Eiq "Latest public release:[[:space:]]*\*\*v${VERSION}\*\*" "$f"; then
        err "$f must not claim draft v${VERSION} as latest public release"
      fi
    fi
  done
else
  # Published Version expectations (existing gate).
  if grep -Eiq 'unreleased draft|do not tag or publish until|latest public release remains' "$NOTES_FILE"; then
    err "$NOTES_FILE contains draft/stale language unsuitable for a GitHub Release body"
  fi
  if ! grep -Eq "^# PHP2Shell v${VERSION}([[:space:]]|$)" "$NOTES_FILE"; then
    err "$NOTES_FILE should start with heading '# PHP2Shell v${VERSION}'"
  fi

  if grep -Eiq "Version in this tree:[[:space:]]*${VERSION}[[:space:]]*\([^)]*unreleased" README.md; then
    err "README.md still describes ${VERSION} as unreleased"
  fi
  if ! grep -Eiq "Latest public release:.*v${VERSION}" README.md; then
    err "README.md should identify v${VERSION} as the latest public release"
  fi

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
if [[ "$UNRELEASED" -eq 1 && -z "$EXPECT_TAG" ]]; then
  echo "check-release-docs: OK (Version=${VERSION}, unreleased development tree)"
else
  echo "check-release-docs: OK (Version=${VERSION}${EXPECT_TAG:+, tag=$EXPECT_TAG})"
fi
