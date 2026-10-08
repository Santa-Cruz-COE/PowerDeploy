<img width="1231" height="265" alt="image" src="https://github.com/user-attachments/assets/433557c1-8995-4e46-87c0-0ff699926e51" />



# PowerDeploy

Powerdeploy is an infrastructure framework for core functionalities of your Windows environment.

Key beneficial features include:

- Replace your print server with a reliable, secure, ultralow cost "serverless" solution

- Speed up your app deployments on endpoints

- Increase the reliability of your app deployments

- Increase the available pool of Windows Store apps from 65% to 99.99%

- Flexibility to Install any script or app of any size remotely

- Increase the flexibility and speed of app setup and management

- Use your own app/script/storage hosting solution (local or cloud) rather than relying on Microsoft's black box unreliable crap 

All of these items are measurable and will be benchmarked and presented here thereafter. 

PowerDeploy is intended for use with InTune, but is designed to be flexible with other remote management systems. 

With PowerDeploy in place, your InTune environment can become to a reliable asset.

---

> **Note:** The rest of this README was drafted with AI. It aims to describe the project accurately, but is archaic and messy. Treat it as an evolving overview rather than exhaustive reference documentation.

**PowerDeploy is a PowerShell framework for packaging, deploying, and managing applications and network printers across cloud-managed Windows fleets (Entra ID + Intune).**

It turns *"I need to deploy this app / this printer"* into a finished, reliable Intune package in minutes — and keeps your entire catalog of deployable assets in version-controlled configuration you actually own, instead of scattered across dozens of hand-built, hard-to-update Intune entries.

Two ideas make that work:

- **A catalog, not a pile of one-off packages.** Every app and printer is a single entry in a JSON manifest. Add an entry and a guided wizard builds the Intune Win32 package, the install/uninstall commands, and the detection script for you — after letting you test the install on a real machine first. (Printers and WinGet, MSI, EXE, and URL-download apps are supported by the wizard today; `Custom_Script` apps can be installed locally but not yet packaged — see [Packaging and managing your assets](#packaging-and-managing-your-assets).)
- **Payloads are pulled at run time, not shipped through Intune.** Intune carries only a small runner. The actual installers come from WinGet or your Azure Blob Storage, and the deployment scripts come from Git, at the moment the endpoint runs. That removes Intune's package-size ceiling, and changing how something deploys means editing a script or one line of JSON — never re-wrapping and re-uploading an app.

It runs **both with and without the Company Portal**: the same definition is available as an assigned / self-service app in Intune *and* runnable on demand by a technician directly on the device.

Built for teams that have gone cloud-first and hit the walls — apps that fail to install at scale, printers that Microsoft's own cloud service can't actually deploy, and a packaging cycle measured in hours per change.

---

## Table of contents

- [The problem it solves](#the-problem-it-solves)
- [Printing: solving what Universal Print can't](#printing-solving-what-universal-print-cant)
  - [Printer manifest format](#printer-manifest-format)
- [Packaging and managing your assets](#packaging-and-managing-your-assets)
- [What you can do with it](#what-you-can-do-with-it)
- [How it works (under the hood)](#how-it-works-under-the-hood)
  - [The runner pattern](#the-runner-pattern)
  - [End-to-end flow](#end-to-end-flow)
  - [Where things live: scripts vs. payloads vs. config](#where-things-live-scripts-vs-payloads-vs-config)
- [With and without the Company Portal](#with-and-without-the-company-portal)
- [Components](#components)
  - [Migrating from a print server](#migrating-from-a-print-server)
- [Repository layout](#repository-layout)
- [Configuration model](#configuration-model)
- [Deployment modes (public vs. private fork)](#deployment-modes-public-vs-private-fork)
- [Logging](#logging)
- [Security](#security)
- [Getting started](#getting-started)
- [License](#license)
- [Support](#support)

---

## The problem it solves

Native Intune is a capable MDM, but several day-to-day deployment tasks are slow, unreliable, or awkward. PowerDeploy was built to address the specific pain points an IT team actually hits:

| Pain point | What PowerDeploy does instead |
|---|---|
| **Win32 app packaging is slow to iterate.** Every script change means re-wrapping, re-uploading, and waiting on sync cycles. | Endpoints pull scripts live from Git. Fix a script, commit, and the next run uses it — no re-upload of the Intune app. |
| **Large/complex installers fail often** through native delivery. | Only a small runner is delivered through Intune. The actual payload comes from WinGet, Azure Blob Storage, or a direct URL at run time. |
| **The Intune Store catalog is limited and often outdated.** | Full real-time access to the WinGet catalog, with handling for the quirks of running WinGet in SYSTEM context. |
| **Update management is clunky.** | WinGet apps can be kept current via [Winget-AutoUpdate](https://github.com/Romanitho/Winget-AutoUpdate); custom apps update by editing the JSON/Blob source, not the Intune entry. |
| **Logging is scattered and vague.** | PowerDeploy's deployment scripts write structured, timestamped, severity-tagged logs to a predictable location under `C:\ProgramData`. |
| **No way to trigger a deployment on demand.** | Scripts live locally on the endpoint and can be launched immediately for testing or urgent installs — no waiting on a sync cycle. |
| **Finding uninstall strings is a treasure hunt.** | A multi-method uninstaller resolves removal automatically (WinGet, MSI, registry, CIM/WMI, AppX). |

---

## Printing: solving what Universal Print can't

Moving to a cloud-based user directory (Entra ID) and device management (Intune) is mainstream now and generally works well. **Printers are where that path tends to break down.** Microsoft's cloud answer is **Universal Print**, and if you've evaluated it for a real environment, you've likely run into the same walls we did:

- **Hardware support is the exception, not the rule.** Universal Print requires printers with native support. In our fleet of ~150 printers — most of them modern and recently in production — only about **10% qualify**. We buy primarily HP, and exactly **one** of our printers supports it natively. Going all-in on UP would mean buying from a narrow approved list and replacing hardware that works perfectly well.
- **The workaround defeats the purpose.** Microsoft's bridge for making non-UP printers work requires an **on-premises connector server** — reintroducing the very on-prem print infrastructure that going cloud was supposed to eliminate, and it doesn't work well even then.
- **It asks you to weaken your security posture.** Registering printers requires loosening settings many organizations (us included) are unwilling to loosen.
- **Deployment is unreliable and hard to troubleshoot**, even where the hardware is supported.

The net result in our environment: **a 0% success rate deploying printers through Universal Print** — not for lack of trying, but because the trade-offs simply don't hold up.

**PowerDeploy replaces the print server, not the printers.** It deploys directly to standard IP printers with no on-prem server, no hardware allow-list, and no change to your security posture:

- Driver packs live as **version-managed files in your Azure Blob Storage** — a centrally managed driver library, not drivers embedded in dozens of packages.
- Each printer is **one entry** in a `PrinterData.json` manifest: name, IP/port, and which driver to use.
- At deploy time the endpoint pulls the right driver pack, stages it with `pnputil`, and creates the port and print queue — in SYSTEM context, fully unattended.
- Define a printer once and it's deployable everywhere: available through the **Company Portal** for assigned devices *and* installable **on demand** by a technician.

The result is the cloud printer management Universal Print promised — that actually works with the printers you already own.

### Printer manifest format

`PrinterData.json` has two lists. The recommended format gives each printer a `PresetDriver` that links to one entry in `drivers`, so many printers can share one driver definition. Alternatively, a printer can define `DriverName`, `INFFile`, and `DriverZip` directly in its own entry. (Example based on [`Templates/PrinterData_TEMPLATE.json`](Templates/PrinterData_TEMPLATE.json).)

```json
{
  "printers": [
    {
      "PrinterName": "Example-HP-Printer",
      "PortName": "010.009.028.106",
      "PrinterIP": "10.9.28.106",
      "PresetDriver": "HP_UPD_PCL6_WIN_X64"
    }
  ],
  "drivers": [
    {
      "PresetDriver": "HP_UPD_PCL6_WIN_X64",
      "DriverName": "HP Universal Printing PCL 6",
      "INFFile": "hpcu345u.inf",
      "DriverZip": "printers/Drivers/HP/HP_Universal_Printing_PCL_6/upd-pcl6-x64-7.9.0.26347.zip"
    }
  ]
}
```

- **`printers[]`** — always includes `PrinterName`, `PortName`, and `PrinterIP`. Use either a `PresetDriver` link or inline `DriverName`, `INFFile`, and `DriverZip` values.
- **`drivers[]`** — shared driver definitions used by `PresetDriver`. Each contains `PresetDriver`, `DriverName` (must match the driver name declared inside the INF), `INFFile` (the bare file name, not a path), and `DriverZip` (the blob path of the driver zip, starting with the container name).
- **Optional printer fields** — `Department`, `Asset`, `Location`, `Model`, and `Verified` are used only to fill in the suggested Intune app name and description. The installer ignores them.
- **The INF doesn't have to sit at the root of the zip.** If it isn't there, the installer searches the zip's subfolders for it, and if it finds more than one copy it picks the one that matches the computer's architecture.

---

## Packaging and managing your assets

Most of the recurring cost of fleet deployment isn't the install itself — it's the **packaging** and the **ongoing upkeep**. PowerDeploy is built to make both cheap, and that's the core of what it offers.

**Packaging is a guided, minutes-long task.** Run [`Setup.ps1`](Setup.ps1), pick (or define) an app or printer, and the wizard:

- optionally **test-installs it on the local machine first**, so you validate the configuration before you ship it;
- builds the **`.intunewin` package** (wrapping the runner) for you — no manual `IntuneWinAppUtil` runs;
- generates the **install command, uninstall command, and detection script**, with parameters Base64-encoded for clean Intune compatibility — no hand-writing detection logic or guessing silent-install switches;
- prints exactly what to paste into each field of the Intune Win32 app form.

> **Which apps the wizard can package today:** the app wizard (`WindowsApp--InTune-Setup`) supports the `WinGet`, `MSI-Private-AzureBlob`, `EXE-Private-AzureBlob`, and `URL_Download` install methods. Apps that use `Custom_Script` (for example Microsoft Office and Dell Command Update) can be installed locally with `WindowsApp--Install-Local`, but the wizard can't package them yet — it builds the `.intunewin`, then stops with an "Unknown Install Method" error before generating the install commands and detection script. The Intune app itself is still created by hand in the Intune portal, using the files and text the wizard produces.

**Management is editing a catalog, not maintaining packages.** Your deployable assets live in JSON manifests — a shared public catalog in this repo and your organization's private catalog in Azure Blob:

- **Add or change an app/printer** → edit one JSON entry. The Intune app entry never has to be rebuilt.
- **Change how an installer behaves** → edit a script and commit. Endpoints pick it up on their next run.
- **Ship a new payload** (updated MSI, newer driver pack) → replace the file in Azure Blob. Nothing in Intune changes.
- **Reuse across the fleet** → define an asset once and deploy it everywhere, via Company Portal or on demand.

This is the difference between maintaining *dozens of brittle, individually-built Intune packages* and maintaining *one catalog behind a runner that always pulls the current version.*

---

## What you can do with it

- **Deploy applications** via WinGet, MSI, EXE, direct URL download, or fully custom installer scripts.
- **Deploy network (IP) printers** with centrally managed driver packs and per-printer JSON config.
- **Uninstall almost anything** through a single multi-method uninstaller.
- **Generate Intune Win32 packages, install/uninstall commands, and detection scripts** automatically from a guided wizard.
- **Push organization configuration** (repo URL and token, container SAS keys, plus the storage account name and manifest paths) to endpoints via Intune remediation scripts.
- **Manage Windows registry and optional features** with safe, ACL-aware operations.
- **Run everything locally on demand** for testing and urgent fixes, independent of the management tool's schedule.

---

## How it works (under the hood)

### The runner pattern

The central design decision is **decoupling orchestration from payload hosting**.

- **Orchestration** (the *logic* — what to install and how) lives in this Git repository.
- **Payloads** (the *bits* — installers, driver ZIPs) live in WinGet or your Azure Blob Storage.
- **The management tool** (Intune/RMM/SCCM) only ever holds [`Git-Runner_TEMPLATE.ps1`](Templates/Git-Runner_TEMPLATE.ps1) — a small, rarely-changing launcher — wrapped in a `.intunewin` package.

When an endpoint runs the package (in **SYSTEM** context), the runner:

1. **Decodes its parameters** — Intune-friendly Base64-encoded JSON is decoded into a normal PowerShell parameter string. This happens first; if decoding fails, the runner stops.
2. **Ensures Git is present** — installs Git for Windows if missing, guarded by a named mutex so parallel deployments don't collide.
3. **Clones or pulls** the target repo into the working directory (e.g. `C:\ProgramData\PowerDeploy--<MODE>\PowerDeploy-Repo`), stashing any local drift first.
4. **Locks down permissions** — runs [`Security_Manager.ps1`](Other_Tools/Security_Manager.ps1) to enforce strict ACLs (SYSTEM + Administrators only) on the working folders, the Intune Management Extension log folder (`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`), and the `HKLM\SOFTWARE\PowerDeploy` registry hive.
5. **Invokes the target script** (an installer, uninstaller, printer install, etc.) with the decoded parameters, capturing every line of output, then runs the Security Manager again.
6. **Logs and exits** with `0` on success or `1` on any failure. The target script's own exit code is written to the Git log but is not passed through to Intune.

Because the runner *pulls the latest commit each time it runs*, iterating on a deployment is just editing a script and committing — the Intune app entry never changes.

### End-to-end flow

```
TECHNICIAN (Setup.ps1, run as admin)
   │
   ├─ Reads org config from HKLM\SOFTWARE\PowerDeploy
   ├─ Picks a deployment mode (dev/test/prod → which repo & branch)
   ├─ Selects an app/printer from JSON (or adds a new one)
   ├─ (optional) Tests the install locally on this machine
   │
   ├─ Make-InTuneWin  ── wraps Git-Runner_TEMPLATE.ps1 ──► .intunewin
   └─ Generate_Install-Command.ps1 ──► install/uninstall commands
                                       + detection script
                                       (params Base64-encoded)
                 │
                 ▼
        Technician uploads to Intune as a Win32 app
                 │
                 ▼
ENDPOINT (SYSTEM context, triggered by Intune or on demand)
   │
   └─ Git-Runner_TEMPLATE.ps1
        ├─ decode Base64 params
        ├─ install Git (mutex-guarded) → clone/pull repo
        ├─ Security_Manager → lock down ACLs
        └─ run target script, e.g. General_JSON-App_Installer.ps1
                 │
                 ├─ WinGet            → Microsoft Store / WinGet catalog
                 ├─ MSI / EXE / URL   → Azure Blob (SAS or AAD) or direct URL
                 └─ Custom_Script     → Office, Dell Command Update, .NET, …
```

### Where things live: scripts vs. payloads vs. config

| Concern | Source of truth | Delivered to endpoint by |
|---|---|---|
| **Deployment logic / scripts** | This Git repo (public or your private fork) | `git clone` / `git pull` at run time |
| **App payloads** | WinGet catalog, Azure Blob Storage, or a direct URL | WinGet, or `DownloadFrom-AzureBlob-*` at run time |
| **Printer drivers** | Driver ZIPs in Azure Blob Storage | Azure Blob download → extract → `pnputil` |
| **What to install (manifest)** | Apps: public catalog `Templates/ApplicationData_TEMPLATE.json` in the repo + private `ApplicationData.json` in Blob. Printers: private `PrinterData.json` in Blob only | Read at run time |
| **Org configuration** | `HKLM\SOFTWARE\PowerDeploy` registry | Set once via Intune remediation scripts |

---

## With and without the Company Portal

The same deployment serves two execution paths from one definition:

- **With Company Portal (managed):** The Win32 app generated by the wizard is assigned in Intune. End users install it self-service from the Company Portal, or it's pushed as required — with a detection script reporting compliance.
- **Without Company Portal (on demand):** Because the repo and scripts are cloned locally into `C:\ProgramData`, a technician can run `Setup.ps1` and install the same app or printer immediately — useful for testing a new package or fixing a machine right now, with no sync-cycle wait.

---

## Components

**Application installers** (general-purpose, parameter-driven):

- [`General_WinGet_Installer.ps1`](Installers/General_WinGet_Installer.ps1) — WinGet installs hardened for SYSTEM context (bootstraps WinGet if missing, resets sources, re-detects after install, retries on failure).
- [`General_MSI_Installer.ps1`](Installers/General_MSI_Installer.ps1) — silent MSI with timeout protection and pre/post-install registry verification.
- [`General_EXE_Installer.ps1`](Installers/General_EXE_Installer.ps1) — EXE installs with **installer-type auto-detection** (InnoSetup, NSIS, InstallShield, WiX Burn, etc.) to infer silent switches.
- [`General_URL_DL_Installer.ps1`](Installers/General_URL_DL_Installer.ps1) — downloads from a URL (file or ZIP), extracts, and hands off to the MSI/EXE installer.
- [`General_JSON-App_Installer.ps1`](Installers/General_JSON-App_Installer.ps1) — **the orchestrator.** Looks up an app in the JSON manifest, resolves prerequisites recursively, and dispatches to the right installer by `InstallMethod`.

**Custom multi-step installers:**

- [`InstallApp-MS_Office-FullClean.ps1`](Installers/InstallApp-MS_Office-FullClean.ps1) — Microsoft 365 Apps with a full clean.
- [`InstallApp-DellCommandUpdate-FullClean.ps1`](Installers/InstallApp-DellCommandUpdate-FullClean.ps1) — Dell Command Update with a full clean.
- [`Install-DotNET.ps1`](Installers/Install-DotNET.ps1), [`Install-WinGet.ps1`](Installers/Install-WinGet.ps1) — framework / tooling bootstrap.

**Printers:**

- [`General_IP-Printer_Installer.ps1`](Installers/General_IP-Printer_Installer.ps1) — reads `PrinterData.json`, downloads the driver ZIP from Azure Blob, stages the driver via `pnputil`, and creates the port and print queue.
- [`Uninstall-Printer.ps1`](Uninstallers/Uninstall-Printer.ps1) — removes a printer by name.

**Uninstallers:**

- [`General_Uninstaller.ps1`](Uninstallers/General_Uninstaller.ps1) — one tool, many methods: WinGet, MSI uninstall strings, registry, CIM/WMI (`Win32_Product`), and AppX/provisioned packages. `UninstallType` selects a method or `All`.
- [`Adobe_Uninstaller_Suite/`](Uninstallers/Adobe_Uninstaller_Suite) — bundled Adobe cleanup utilities.

**Downloaders (Azure Blob):**

- [`DownloadFrom-AzureBlob-SAS.ps1`](Downloaders/DownloadFrom-AzureBlob-SAS.ps1) — SAS-token auth (works in SYSTEM context; the primary method).
- [`DownloadFrom-AzureBlob-AADauth.ps1`](Downloaders/DownloadFrom-AzureBlob-AADauth.ps1) — Azure AD / connected-account auth (runs in user context, uses the `Az` modules).

**Configurators:**

- [`Configure-Registry.ps1`](Configurators/Configure-Registry.ps1) — read / backup / modify / lock-down registry with explicit 32- and 64-bit view handling.
- [`Configure-WindowsOptionalFeatures.ps1`](Configurators/Configure-WindowsOptionalFeatures.ps1) — enable/disable Windows optional features.

**Templates** (cloned to endpoints and/or used to generate artifacts):

- [`Git-Runner_TEMPLATE.ps1`](Templates/Git-Runner_TEMPLATE.ps1) — the endpoint runner described above.
- [`Detection-Script-Application_TEMPLATE.ps1`](Templates/Detection-Script-Application_TEMPLATE.ps1) / [`Detection-Script-Printer_TEMPLATE.ps1`](Templates/Detection-Script-Printer_TEMPLATE.ps1) — Intune detection scripts.
- [`General_RemediationScript-Registry_TEMPLATE.ps1`](Templates/General_RemediationScript-Registry_TEMPLATE.ps1) / [`OrganizationCustomRegistryValues-Reader_TEMPLATE.ps1`](Templates/OrganizationCustomRegistryValues-Reader_TEMPLATE.ps1) — push and read org config in the registry.
- [`ApplicationData_TEMPLATE.json`](Templates/ApplicationData_TEMPLATE.json) — the live public app catalog (read directly at run time). [`PrinterData_TEMPLATE.json`](Templates/PrinterData_TEMPLATE.json) — a starter example of the printer manifest format (not used for deployments; Setup only shows it as an example).

**Tooling:**

- [`Setup.ps1`](Setup.ps1) — the technician's main entry point (guided wizards + local install/uninstall + config remediation generation). Its menu is built when it starts, so the numbers can change; the functions are:
  - `Adobe-Apps-FullCleanup--Uninstall-Local` — runs the bundled Adobe full-cleanup uninstaller on this machine.
  - `Printer--Convert-Vendor-DriverPack` — turns a manufacturer's driver pack into a PowerDeploy driver zip (see [Migrating from a print server](#migrating-from-a-print-server)).
  - `Printer--InTune-Setup` — packages a printer from `PrinterData.json` for Intune.
  - `Printer--Install-Local` / `Printer--Uninstall-Local` — installs or removes a printer on this machine.
  - `Registry_Remediations--InTune-Setup` — generates the detection/remediation scripts that push org configuration to the registry, and can optionally also build a `.intunewin` of the remediation script.
  - `WindowsApp--InTune-Setup` — packages an app from the catalog for Intune (not `Custom_Script` apps yet).
  - `WindowsApp--Install-Local` — installs a catalog app on this machine.
  - `WindowsApp--Uninstall-Local` — opens a sub-menu of search-and-uninstall methods for this machine: `AppPackage`, `CIM`, and `Registry`.
- [`Generate_Install-Command.ps1`](Other_Tools/Generate_Install-Command.ps1) — builds the Base64-encoded Intune install/uninstall commands and detection scripts.
- [`Security_Manager.ps1`](Other_Tools/Security_Manager.ps1) — enforces strict ACLs on PowerDeploy folders and registry.
- Print-server migration tools — [`Export-PrinterServer-CSV.ps1`](Other_Tools/Export-PrinterServer-CSV.ps1), [`Convert-PrinterCSV-ToJSON.ps1`](Other_Tools/Convert-PrinterCSV-ToJSON.ps1), [`Export-PrinterServer-Drivers.ps1`](Other_Tools/Export-PrinterServer-Drivers.ps1), and [`Convert-VendorPack-ToDriverZip.ps1`](Other_Tools/Convert-VendorPack-ToDriverZip.ps1). See below.

### Migrating from a print server

These four tools turn an existing Windows print server into `PrinterData.json` entries and driver zips. None of them changes your live `PrinterData.json` or uploads anything — you review the output and merge it by hand. Output goes under `TEMP\` in the PowerDeploy working directory; if the scripts aren't running from inside a PowerDeploy install (no `..\..\TEMP` folder), they write to a `TEMP\` folder inside the script's own folder (`Other_Tools\TEMP\`) instead.

1. **Export the print queues** — run [`Export-PrinterServer-CSV.ps1`](Other_Tools/Export-PrinterServer-CSV.ps1) (or `Export-PrinterServer-CSV_RUNNER.bat`) **on the print server, as administrator**. It exports every printer queue on the server to `TEMP\PrintServer_Exports\<SERVER>.Export.<timestamp>.csv`, with these columns:
   - `PrinterName`, `PrinterIP`, `PortName` (pre-filled as the zero-padded IP, e.g. `010.009.028.106`), a **suggested** `PresetDriver` code, `DriverName`, and `INFFile` (bare file name).
   - `Location` and `Comment` copied from the queue; `Model`, `Asset`, and `Department` left blank for you to fill in.
   - Columns ending in `_EXCLUDED` (raw port name, padded IP, full INF path) are for reference only and are never written to the JSON.
2. **Review the CSV** — check names and ports, remove queues you don't want to migrate, and rename `PresetDriver` codes to your own convention. Printers that share a driver should share the same `PresetDriver` value.
3. **Convert it to JSON** — run [`Convert-PrinterCSV-ToJSON.ps1`](Other_Tools/Convert-PrinterCSV-ToJSON.ps1) (or `Convert-PrinterCSV-ToJSON_RUNNER.bat`). Pass `-CsvPath`, or leave it out to pick from the CSVs in `TEMP\PrintServer_Exports`; `-OutputPath` is optional. It writes `<csv name>.PrinterData.json` with a `printers[]` list and a de-duplicated `drivers[]` list.
   - Any extra column is carried into the printer entries that have a value for it; blank cells are left out.
   - If one `PresetDriver` code covers two different INF files (different driver versions), the tool splits it into separate codes and tells you.
   - Each driver's `DriverZip` is a placeholder for you to fill in: `printers/Drivers/<Vendor>/PASTE_ZIP_FILENAME_HERE.zip` (or `.../PASTE_ZIP_FOR_<inf>_HERE.zip` for a split entry).
4. **Get the driver zips**, from either source:
   - **From the print server** — run [`Export-PrinterServer-Drivers.ps1`](Other_Tools/Export-PrinterServer-Drivers.ps1) on the print server. It zips each in-use driver's folder from the Windows Driver Store into `TEMP\PrintServer_Drivers\` and writes matching `drivers[]` entries to `<SERVER>.drivers.json`. Options: `-Analyze` (list only, build nothing), `-DriverName` (one driver), `-AllInstalled` (every installed driver, not just ones in use), `-IncludeMicrosoft` (include Windows built-in drivers), `-BlobPathPrefix` (default `printers/Drivers`), and `-OutputDirectory`. Admin rights are only needed for a driver that isn't in the Driver Store.
   - **From a manufacturer's driver pack** — on an admin workstation, run [`Convert-VendorPack-ToDriverZip.ps1`](Other_Tools/Convert-VendorPack-ToDriverZip.ps1) `-PackPath <pack>`, or use Setup's `Printer--Convert-Vendor-DriverPack`. It accepts a vendor `.zip`, a self-extracting `.exe` (needs 7-Zip installed), or an already-extracted folder. It reads the INFs to find the real printer driver; if more than one INF still matches, it asks you to choose. Options: `-DriverName`, `-PresetDriver`, `-Analyze`, `-BlobPathPrefix`, and `-OutputDirectory`. Output: `TEMP\DriverPacks\<pack>-<arch>.zip` plus `<pack>.driver-entry.json`.
5. **Upload the zips** to your printers container in Azure Blob.
6. **Fill in the placeholders** — set each `DriverZip` to the zip's blob path, and check that every printer's `PresetDriver` matches a `drivers[]` entry.
7. **Merge** the reviewed `printers[]` and `drivers[]` entries into your private `PrinterData.json` in Azure Blob.

---

## Repository layout

```
PowerDeploy/
├─ Setup.ps1                  # Technician entry point (run as admin)
├─ Setup_RUNNER.bat
├─ Installers/                # WinGet, MSI, EXE, URL, JSON orchestrator, custom installers
├─ Uninstallers/              # General multi-method uninstaller, printer, Adobe suite
├─ Downloaders/               # Azure Blob (SAS + AAD)
├─ Configurators/             # Registry + Windows optional features
├─ Templates/                 # Git runner, detection/remediation scripts, JSON manifests
├─ Other_Tools/               # Install-command generator, Security Manager, print-server migration tools, utilities
├─ Tests/
├─ LICENSE.md  /  NOTICE.md
└─ README.md
```

---

## Configuration model

Per-organization settings live in the registry under **`HKLM\SOFTWARE\PowerDeploy`**, organized into three subkeys. They're typically deployed fleet-wide using the **Intune remediation scripts** that `Setup.ps1` can generate, and read at run time by [`OrganizationCustomRegistryValues-Reader_TEMPLATE.ps1`](Templates/OrganizationCustomRegistryValues-Reader_TEMPLATE.ps1).

| Subkey | Value | Purpose |
|---|---|---|
| `\General` | `StorageAccountName` | Azure Storage account hosting payloads & private JSON |
| `\General` | `CustomRepoURL` | Your private fork's Git URL (for production) |
| `\General` | `CustomRepoToken` | OAuth token for the private repo (optional) |
| `\Printers` | `PrinterDataJSONpath` | Blob path to `PrinterData.json` |
| `\Printers` | `PrinterContainerSASkey` | SAS token for the printers container |
| `\Applications` | `ApplicationDataJSONpath` | Blob path to `ApplicationData.json` |
| `\Applications` | `ApplicationContainerSASkey` | SAS token for the applications container |

The hive is ACL-locked to SYSTEM + Administrators by the Security Manager.

**JSON manifests** describe *what* is available to deploy. Apps are searched sequentially: first the **public** catalog in this repo at `Templates/ApplicationData_TEMPLATE.json` (despite the name, the installers and `Setup.ps1` read this file directly as the live public catalog), then the private `ApplicationData.json` in your Azure Blob if no public match is found. A public entry therefore takes precedence over a private entry with the same `ApplicationName`. Printers have no public catalog: they are read only from the private `PrinterData.json` in your Azure Blob. `Templates/PrinterData_TEMPLATE.json` is just a starter example of the format (see [Printer manifest format](#printer-manifest-format)).

Each app entry declares an `InstallMethod` (`WinGet`, `MSI-Private-AzureBlob`, `EXE-Private-AzureBlob`, `URL_Download`, `Custom_Script`) plus the fields that method needs, and optional `PreRequisites`.

---

## Deployment modes (public vs. private fork)

PowerDeploy is meant to be **forked into a private organization repo**. The public repo carries shared logic and the community app catalog; your private fork carries your org's customizations and is what production endpoints pull from.

`Setup.ps1` asks which of four **deployment modes** an artifact should target, which selects the repo + branch the generated package will pull from at run time:

| Mode | Repo | Branch | Use it for |
|---|---|---|---|
| `PUBLIC-DEVELOPMENT` | Official public repo | `dev` | Testing public development code |
| `PUBLIC-TESTING` | Official public repo | `main` | Testing the latest public code before merging it into your fork |
| `PRIVATE-DEVELOPMENT` | Your fork (`CustomRepoURL`) | `dev` | Testing your own changes |
| `PRODUCTION` | Your fork (`CustomRepoURL`) | `main` | Real deployments |

The two private modes require `CustomRepoURL` to be set in the registry (see [Configuration model](#configuration-model)); Setup won't let you pick them until it is. If `CustomRepoToken` is set, it's used to authenticate to your fork.

Each mode installs into its own `C:\ProgramData\PowerDeploy--<MODE>` working directory (for example `C:\ProgramData\PowerDeploy--PRODUCTION`) so test and production payloads stay isolated on the same machine.

> Detailed setup of the private fork, Azure Blob containers, and SAS/AAD configuration is intended to be documented separately as the project matures.

---

## Logging

Scripts write structured logs under the working directory, e.g. `C:\ProgramData\PowerDeploy--<MODE>\Logs\`, split by area:

| Folder | Written by |
|---|---|
| `Git_Logs` | The Git runner (and the test harness) |
| `Installer_Logs` | App and printer installers |
| `Uninstaller_Logs` | General uninstaller, printer uninstaller, Adobe cleanup |
| `Detection_Logs` | Intune detection scripts and the registry remediation script |
| `Config_Logs` | Registry and Windows optional-feature configurators |
| `Setup_Logs` | `Setup.ps1` |
| `Security_Logs` | Security Manager |
| `Download_Logs` | Azure Blob downloaders |
| `Generator_Logs` | `Generate_Install-Command.ps1` |
| `Other_Logs` | `Convert-VendorPack-ToDriverZip.ps1`, `Generate_Custom-Script_FromTemplate.ps1` |
| `Repair_Logs` | `General_Windows-Fixer.ps1` |

The print-server migration tools `Export-PrinterServer-CSV.ps1`, `Convert-PrinterCSV-ToJSON.ps1`, and `Export-PrinterServer-Drivers.ps1` write to the console only — they don't create log files.

Each entry is timestamped and tagged with a severity level (`INFO`, `WARNING`, `ERROR`, `SUCCESS`) and color-coded in the console. Because everything lands in a predictable, per-area location, troubleshooting a failed deployment is reading one log rather than correlating across the Intune Management Extension logs.

---

## Security

- **Runs in SYSTEM context** on managed endpoints, with the working directory under `C:\ProgramData` (not visible to standard users by default).
- **ACL enforcement** via the Security Manager: working folders, the Intune Management Extension log folder (`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`), and the `HKLM\SOFTWARE\PowerDeploy` hive are restricted to SYSTEM + Administrators, with inheritance broken.
- **Path validation** guards against malformed/injection-prone paths before any file or registry operation runs.
- **Azure Blob access** uses scoped, read-only SAS tokens (or AAD for user-context scenarios) rather than embedded account keys.

---

## Getting started

> High-level only — assumes Intune + an Azure Storage account.

**Before you run `Setup.ps1`:**

- **Run it as administrator** (or run `Setup_RUNNER.bat` as administrator). It uses Windows PowerShell 5.1 (`powershell.exe`), which is built into Windows.
- **To test WinGet installs locally, run it as the logged-in user who is also an administrator.** WinGet won't work properly otherwise, and Setup warns you. You can still use Setup to package apps for Intune either way.
- **Keep it in the standard location.** Setup expects its repo folder to sit inside a `C:\ProgramData\PowerDeploy…` folder. If it's anywhere else, it warns that it will lock down (restrict to SYSTEM + Administrators) the `Temp` and `Logs` folders in the repo's parent folder, and the repo folder itself — then waits for you to press Enter to continue.

1. **Fork** this repo into your organization's private repo (for production use).
2. **Stand up Azure Blob Storage**: containers for application payloads and printer drivers, plus your private `ApplicationData.json` / `PrinterData.json`.
3. **Generate and deploy the config remediation** from `Setup.ps1` (`Registry_Remediations--InTune-Setup`) to populate `HKLM\SOFTWARE\PowerDeploy` on your fleet. The wizard only asks for four values: your private repo URL, the repo token, and the printer and application container SAS keys. The other three are fixed defaults in the `RegRemediationScript` function of [`Other_Tools/Generate_Install-Command.ps1`](Other_Tools/Generate_Install-Command.ps1): `StorageAccountName` = `powerdeploy`, `PrinterDataJSONpath` = `printers/PrinterData.json`, and `ApplicationDataJSONpath` = `applications/ApplicationData.json`. **If your storage account name, container names, or manifest paths are different, edit those defaults (in your private fork) before generating the scripts.**
4. **Run `Setup.ps1` as an administrator** and follow a wizard to add an app or printer: it can test the install locally, then produce the `.intunewin`, the install/uninstall commands, and the detection script. (`Custom_Script` apps can't be packaged by the wizard yet — see [Packaging and managing your assets](#packaging-and-managing-your-assets).)
5. **Create the Win32 app in Intune** using those generated artifacts, and assign it.

---

## License

Licensed under the **Apache License 2.0** — see [LICENSE.md](LICENSE.md). Trademark and attribution terms are in [NOTICE.md](NOTICE.md).

Copyright © Santa Cruz County Office of Education.

## Support

For issues and feature requests, please use the [GitHub Issues](https://github.com/Santa-Cruz-COE/PowerDeploy/issues) page.

---

**Source:** <https://github.com/Santa-Cruz-COE/PowerDeploy>

> **Note:** Portions of this README were drafted with AI assistance and describe an evolving project. Verify specifics against the scripts themselves before relying on them in production.

<p align="center">
  <img src="https://github.com/user-attachments/assets/38b2e30d-dd82-4681-a18a-4e7c96e23d9b" />
</p>
