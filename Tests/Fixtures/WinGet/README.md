# WinGet show fixtures

Stdout of `winget show` used by the parser tests (cases D07*) in
`Tests/IntuneGraphUpload.Tests.ps1`. The tests never run winget.exe; they parse these files.

Captured on 2026-10-12 with WinGet **v1.29.380** (Windows 11 Enterprise 10.0.26100), using a hidden
redirected process (no console attached, so no ANSI or spinner output was emitted) and the arguments:

    show --id <ID> --exact --source <msstore|winget> --disable-interactivity --accept-source-agreements

| File | Kind | Source / ID | Notes |
|---|---|---|---|
| `msstore-9WZDNCRFJ3PZ.txt` | captured | msstore / 9WZDNCRFJ3PZ (Company Portal) | Multiline description; continuation lines end in CR CR LF; contains non-ASCII (en dash, curly apostrophe, copyright sign); next field `License:` |
| `winget-Microsoft.VisualStudioCode.txt` | captured | winget / Microsoft.VisualStudioCode | Description on the label line; next field `Homepage:` |
| `winget-Git.Git.txt` | captured | winget / Git.Git | Multiline description (label alone); next field `Homepage:`; has a multiline `Release Notes:` section |
| `winget-7zip.7zip.txt` | captured | winget / 7zip.7zip | Description on the label line; `Author:`, `Release Notes:` on its label line, `Documentation:` |
| `notfound.txt` | captured | winget / Contoso.DoesNotExist.PDTest | `No package found matching input criteria.` (exit code -1978335212); a community ID against msstore prints the same text |
| `synth-localized-de.txt` | synthesized | - | Hand-made German labels; must be UnrecognizedOutput |

The ANSI/spinner, wrong-ID header, and unknown-boundary inputs are built inline in the tests from the
captured English shape. The captured files are raw bytes (UTF-8, no BOM) and are intentionally not
ASCII-only; do not re-save them through an editor that changes line endings.
