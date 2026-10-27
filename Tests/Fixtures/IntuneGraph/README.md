# Tests/Fixtures/IntuneGraph

Fixture input for `Tests/IntuneGraphUpload.Tests.ps1` (spec sections 10.1 and 13, cases P01/P02).

## Provenance

**Every file in this folder is synthesized.** Nothing here came from a vendor, a tenant, or a
production package, and no real key material appears in any fixture - the base64 blocks in
`Detection.xml` are generated from a fixed arithmetic pattern by the generator script.

The *shape*, however, is not invented. `IntuneWinPackage/Metadata/Detection.xml` was read out of a
real `IntuneWinAppUtil 1.8.7.0` package built on this workstation (a 129 MB vendor sensor
package, deliberately **not** copied into the repo) on 2026-10-08, and the fixture reproduces:

- the outer ZIP layout: exactly the two entries
  `IntuneWinPackage/Contents/<FileName>` and `IntuneWinPackage/Metadata/Detection.xml`,
- entries **stored uncompressed** (`Stored`, not `Deflate`), as IntuneWinAppUtil writes them,
- the `ApplicationInfo` element names, nesting, and document order:
  `Name`, `UnencryptedContentSize`, `FileName`, `SetupFile`,
  `EncryptionInfo/{EncryptionKey, MacKey, InitializationVector, Mac, ProfileIdentifier, FileDigest, FileDigestAlgorithm}`,
  with `ToolVersion="1.8.7.0"` on the root element,
- the real-world size relationship: `UnencryptedContentSize` (462) is **smaller** than the payload
  stored in the archive (512). The observed package showed the same 50-byte envelope overhead at
  the megabyte scale, which is exactly why `size` must come from the XML and `sizeEncrypted` must
  be measured from the payload.

## Regenerating

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File Tests\Fixtures\IntuneGraph\New-PDIntuneWinFixture.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File Tests\Fixtures\IntuneGraph\New-PDIntuneWinFixture.ps1 -Verify   # read-only listing
```

Use **pwsh 7**. Windows PowerShell 5.1's `ZipArchive` deflates entries even when asked to store
them, which would rewrite every fixture with different bytes; the generator probes for that and
refuses (exit 3, no files touched) rather than producing a diff that looks intentional. Pass
`-Force` only if that is actually what you want.

## The fixtures

| File | Parser must | Why it exists |
|---|---|---|
| `valid.intunewin` | read | The reference package: metadata + exactly one stored content entry. |
| `deflated-payload.intunewin` | read | Same content, DEFLATED entries (unlike a real package). Proves the reader goes through the archive API and never assumes `Stored`. |
| `missing-detection-xml.intunewin` | reject | No `Detection.xml` at all - nothing tells us the file name, sizes, or encryption info. |
| `metadata-without-content-entry.intunewin` | reject | Metadata names `IntunePackage.intunewin`; the archive contains only `RenamedPackage.intunewin`. A metadata/payload mismatch must never be "helpfully" resolved. |
| `two-content-entries.intunewin` | reject | Two entries under `Contents/`. Spec 10.1 requires one unambiguous pairing; picking the first match is a defect. |
| `traversal-entry.intunewin` | reject | Contains an entry named `IntuneWinPackage/Contents/../../../../PowerDeploy-fixture-evil.txt`. Archive entry names are never used as output paths. |
| `not-a-zip.intunewin` | reject | 96 bytes with no ZIP header - a truncated or mislabelled file must produce a preflight error, not an unhandled .NET exception. |
| `malformed-detection-xml.intunewin` | reject | `Detection.xml` truncated mid-document. |
| `missing-encryption-info.intunewin` | reject | Valid package but no `EncryptionInfo`, so a commit could never be built. Fails at preflight, not halfway through an upload. |

The tests read these files; they never write to this directory. The parser extracts the payload
into a per-run temp directory, which the tests create under `$env:TEMP` and delete themselves.
