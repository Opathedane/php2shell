## Summary

- Stabilization branch for **v2.7.2**: enterprise QA (assessment accuracy, console/HTML, WAF/status) plus distribution docs (Intune, GPO, PSADT, report collection, licensing/signing gates).
- Acceptance pass: HTML hierarchy fix (Recommended next steps before optional IR); humanized SAPI card wording; release acceptance checklist + field tests.
- **Do not merge** until maintainer review. **Do not tag/publish** from this PR automatically.

## Test plan

- [x] `go test` / `go vet` / release-docs check on branch tip
- [ ] CI green on Draft PR
- [ ] Maintainer visual open of `testdata/examples/v2.7.2-qa/*.html`
- [ ] Field pilots per `docs/FIELD-ACCEPTANCE-TESTS-2.7.2.md` (Windows / Intune / GPO / 2012 R2)
- [ ] LICENSE decision before unrestricted public distribution
- [ ] Prefer tag **v2.7.2** for stabilization; reserve **v2.8.0** for public milestone

## Notes

Reviewed commit must be the exact SHA used for any future `gh release create --target`.
