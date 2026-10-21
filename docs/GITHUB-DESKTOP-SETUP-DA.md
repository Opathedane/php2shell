# Sæt PHP2Shell op på din Mac med GitHub Desktop

Dette er en komplet kildekodepakke til **v2.1.0-alpha.2**. Den indeholder bl.a. de skjulte GitHub Actions-workflows i `.github/workflows/`.

**Vigtigt:** Dette er kildekoden, ikke en færdig, produktionsgodkendt PHP2Shell-detektor. Der er endnu ingen verificerede PHP2Shell-specifikke IOC-regler i pakken.

## Brug dit eksisterende repository

1. Åbn **GitHub Desktop**. Vælg **File → Clone Repository…** og vælg fanen **GitHub.com** eller **URL**.
2. Vælg `Opathedane/php2shell` og klon det til `~/Developer/php2shell`. GitHub Desktop kan bede dig vælge `~/Developer` som overordnet mappe. Hvis du får fejl om, at den tomme `php2shell`-mappe allerede findes, så slet **kun den tomme mappe** i Finder og prøv kloningen igen.
3. Pak denne ZIP ud i Downloads. Åbn den udpakkede mappe, og brug `Cmd + Shift + .` i Finder for at vise skjulte filer. Det er vigtigt, fordi `.github` og `.gitignore` ellers kan blive overset.
4. Kopiér **alle filer og mapper inde i** den udpakkede pakke til `~/Developer/php2shell`, og vælg **Erstat** for eksisterende filer. **Slet ikke** den `.git`-mappe, som GitHub Desktop oprettede ved kloningen.
5. Åbn GitHub Desktop, kontrollér ændringerne under **Changes**, og kontrollér at `.github/workflows/ci.yml`, `build-preview.yml` og `release-alpha.yml` er med.
6. Skriv commit-beskeden `feat: complete standalone scanner alpha and CI workflows`, klik **Commit to main** og derefter **Push origin**.
7. Tjek https://github.com/Opathedane/php2shell/actions . CI skal bestå før du bruger den manuelle workflow **Publish standalone ALPHA downloads**. Workflowen opretter en offentlig *prerelease*; del ikke downloads til kunder som en fuldt valideret scanner.

## Kontrol af de vigtigste filer

- `cmd/php2shell/main.go`: CLI-indgang
- `internal/audit/`, `internal/rules/`: scanner og signaturverifikation
- `rules/`: tom IOC-template og regler for publicering
- `.github/workflows/`: tests, preview-build og alpha-release
- `.gitignore`: forhindrer lokale rapporter og binaries i utilsigtet commit
- `docs/INSTALL-FOR-CONSULTANTS.md`: brugervejledning til færdigbyggede executables

GitHub Desktop genkender kun en mappe som det **eksisterende** repository, hvis kloningens `.git`-historik følger med. ZIP-filen indeholder bevidst ikke `.git`, fordi den ikke skal erstatte repoets historie.
