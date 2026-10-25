# Project presentation recommendations

Guidance for GitHub repository settings and public messaging. Apply in the GitHub UI; this file is not applied automatically.

## Suggested repository description

```
Read-only PHP discovery and upstream patch-review scanner for authorized Windows and Linux hosts. HTML reports only. Not a compromise clearance tool.
```

## Suggested topics

`php`, `security`, `vulnerability-assessment`, `iis`, `linux`, `windows`, `html-report`, `incident-response`, `patch-management`

Avoid topics that imply exploitation, webshell generation, or “clean bill of health.”

## README structure (implemented in root README)

1. One-sentence purpose + non-certification warning  
2. Current release pointer  
3. Getting started (download → verify → doctor → scan)  
4. Supported-platform matrix  
5. Report coverage table + official fix versions  
6. Known limitations  
7. Release verification  
8. Documentation index + feedback + contact + licensing caveat  

## Getting started (short form for social / internal wiki)

1. Authorize the engagement.  
2. Download v2.3.0 (or latest) for the OS/arch.  
3. Check `SHA256SUMS`.  
4. `php2shell doctor` then `php2shell scan`.  
5. Read the HTML report coverage and next steps; do not treat exit code `0` as clearance.

## About section checklist

- [ ] Description set (above)  
- [ ] Website: leave empty or point to Releases / internal runbook  
- [ ] Topics set  
- [ ] Releases featured; prerelease alphas not marked Latest  
- [ ] Security policy link visible (`SECURITY.md`)  
- [ ] Issues enabled with templates; Discussions optional  

## Tone

Professional, evidence-qualified, suitable for administrators and cybersecurity consultants. Prefer “patch review required” over “vulnerable/safe.” Keep security limitations visible above the fold in README and release notes.
