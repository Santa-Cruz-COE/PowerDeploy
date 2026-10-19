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

- **A catalog, not a pile of one-off packages.** Every app and printer is a single entry in a JSON manifest. Add an entry and a guided wizard builds the Intune Win32 package, the install/uninstall commands, and the detection script for you — after letting you test the install on a real machine first — and can optionally create the app in Intune for you as well ([Publishing to Intune automatically](#publishing-to-intune-automatically-optional)). (Printers and WinGet, MSI, EXE, and URL-download apps are supported by the wizard today; `Custom_Script` apps can be installed locally but not yet packaged — see [Packaging and managing your assets](#packaging-and-managing-your-assets).)
- **Payloads are pulled at run time, not shipped through Intune.** Intune carries only a small runner. The actual installers come from WinGet or your Azure Blob Storage, and the deployment scripts come from Git, at the moment the endpoint runs. That removes Intune's package-size ceiling, and changing how something deploys means editing a script or one line of JSON — never re-wrapping and re-uploading an app.

It runs **both with and without the Company Portal**: the same definition is available as an assigned / self-service app in Intune *and* runnable on demand by a technician directly on the device.

Built for teams that have gone cloud-first and hit the walls — apps that fail to install at scale, printers that Microsoft's own cloud service can't actually deploy, and a packaging cycle measured in hours per change.

---

## Table of contents

- [The problem it solves](#the-problem-it-solves)
- [Printing: solving what Universal Print can't](#printing-solving-what-universal-print-cant)
  - [Printer manifest format](#printer-manifest-format)
- [Packaging and managing your assets](#packaging-and-managing-your-assets)
  - [Publishing to Intune automatically (optional)](#publishing-to-intune-automatically-optional)
  - [Bulk printer tools (optional)](#bulk-printer-tools-optional)
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
- then either prints exactly what to paste into each field of the Intune Win32 app form (**guided manual setup**), or creates the app in Intune for you (**automatic setup via the API**, optional — see below).

> **Which apps the wizard can package today:** the app wizard (`WindowsApp--InTune-Setup`) supports the `WinGet`, `MSI-Private-AzureBlob`, `EXE-Private-AzureBlob`, and `URL_Download` install methods. Apps that use `Custom_Script` (for example Microsoft Office and Dell Command Update) can be installed locally with `WindowsApp--Install-Local`, but the wizard can't package them yet — it builds the `.intunewin`, then stops with an "Unknown Install Method" error before generating the install commands and detection script. In guided mode the Intune app is created by hand in the Intune portal, using the files and text the wizard produces; in automatic mode Setup creates it.

**Management is editing a catalog, not maintaining packages.** Your deployable assets live in JSON manifests — a shared public catalog in this repo and your organization's private catalog in Azure Blob:

- **Add or change an app/printer** → edit one JSON entry. The Intune app entry never has to be rebuilt.
- **Change how an installer behaves** → edit a script and commit. Endpoints pick it up on their next run.
- **Ship a new payload** (updated MSI, newer driver pack) → replace the file in Azure Blob. Nothing in Intune changes.
- **Reuse across the fleet** → define an asset once and deploy it everywhere, via Company Portal or on demand.

This is the difference between maintaining *dozens of brittle, individually-built Intune packages* and maintaining *one catalog behind a runner that always pulls the current version.*

### Publishing to Intune automatically (optional)

Instead of copying the wizard's output into the Intune portal by hand, Setup can create the Win32 app for you through Microsoft Graph: upload the package, set the description, notes, category and detection script, assign it, and then read everything back to confirm Intune stored exactly what was sent. It is **opt-in and runs on an admin workstation only** — managed computers are not involved and never receive the credential. Without it, the guided walkthrough works exactly as before.

**One-time setup** — run `Setup.ps1` → `InTuneAPI--Setup-and-Manage`:

| Option | Use it to |
|---|---|
| 1 - Azure App Registration - Setup/Config | **Automatic:** sign in as an administrator; Setup creates an app registration named `PowerDeploy Intune Upload` (or reuses an existing one with that exact name, as it is), grants it two Microsoft Graph application permissions (`DeviceManagementApps.ReadWrite.All`, `Group.Read.All`), and creates, tests and saves a secret for this PC. **Manual:** enter the tenant ID, client ID and secret of an existing registration; it is saved only if it passes the test. |
| 2 - Azure App Registration - Test config | Check the saved credential works (read-only). |
| 3 - Azure App Registration - Rotate local PC secret | Replace this PC's secret (admin sign-in required). The new secret is tested before the old one is revoked; if the new one fails, the old one stays saved and working. |
| 4 - Azure App Registration - Remove local PC secret | Delete this PC's saved secret, optionally revoking it in Entra (admin sign-in required for revoking; if revoking fails, the file is kept so you still know which secret to revoke). |
| 5 - MAA Exclusions - Setup/Config manually | Show the portal steps for Multi-Admin Approval (below). |

- **Who can run setup:** granting Microsoft Graph application permissions needs **Privileged Role Administrator** or **Global Administrator**. If you don't hold those, have someone who does create the registration and use the *Manual* choice.
- **Admin sign-in prerequisite:** Automatic setup, rotation, and removal-with-revocation each open a temporary administrator sign-in, which needs the `Microsoft.Graph.Authentication` module (uploads themselves don't). If it is missing, Setup offers to install it for your Windows account from the PowerShell Gallery; or install it yourself with `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`. The Microsoft sign-in screen names *Microsoft Graph Command Line Tools* (Microsoft's app for Graph PowerShell); leave **Consent on behalf of your organization** unchecked.
- **Where the secret lives:** `%LOCALAPPDATA%\PowerDeploy\GraphUpload\credential.clixml`, encrypted with Windows DPAPI for your Windows account only. Lifetime is chosen at setup (default 180 days, up to 730); Setup warns 30 days before expiry. Automatic setup gives each admin PC its own secret; with Manual entry, avoid sharing one secret between PCs.
- **Multi-Admin Approval (MAA):** if your tenant requires a second admin to approve app changes, add `PowerDeploy Intune Upload` to the **Exclusions** of the MAA *apps* access policy (Intune → Tenant administration → Multi Admin Approval → Access policies; option 5 prints the exact steps). The exclusion covers only uploads made by that app registration; changes made in the portal still need approval. It survives secret rotation.

**Publishing** — in `Printer--InTune-Setup` or `WindowsApp--InTune-Setup`, choose **2 - Automatic setup via the API** when asked:

1. Enter **Required** and then **Available** targets, separated by `;` — exact group names (letter case doesn't matter) or group object IDs, or `/AllDevices` / `/AllUsers` for Intune's built-in targets (e.g. `/AllDevices; Techs`). Leave both blank for no assignments. A typo is reported and you can re-enter the lists.
2. Setup runs a **dry run** (nothing is created) and shows a review: name, publisher, version, description, notes, category, assignments, duplicate app names, and the secret's expiry.
3. Confirm (and confirm again separately if an app with the same name already exists). Setup uploads, waits for Intune to publish, assigns, and verifies. On success it shows the new app's ID and portal link.
4. If anything fails, Setup deletes the half-created app; if it can't, it shows the leftover app's ID so you can remove it. Either way you continue with the guided walkthrough — Setup never exits on a failure.

**What goes where:** the **Description** (shown to users in the Company Portal) is, for printers, `Department`, `Location`, `Model`, `Asset` and `PrinterIP` (`N/A` for any that are blank); for apps, the catalog's `AppDescription`, or — for WinGet apps without one — the description from `winget show` (Microsoft Store first, then the WinGet community source), else `N/A`. Printers also get the standard icon [`Templates/Printer-Icon.png`](Templates/Printer-Icon.png) (replace that file to use your own); apps can name one with `IconFile` (a PNG/JPEG in the repo) or `IconUrl` (an `https` link, downloaded at publish time). The Company Portal **information and privacy links** come from the catalog's `InformationUrl` / `PrivacyUrl`, or — for WinGet apps — from `winget show` (`Homepage`, else `Publisher Url`; `Privacy Url`). Icons and links are set in a separate best-effort step, so a problem with them is a warning, never a failed upload. The **Publisher** is the catalog's `Publisher`, else (WinGet apps) the publisher `winget show` reports, else `PowerDeploy`. The **Version** is the catalog's `PackagedVersion` or `Version`, else the PowerDeploy source commit (printers always use the commit) — never WinGet's version number, since WinGet installs the latest release on each device. The **Notes** (admin-only) hold the technical block: target and source repo/branch, source commit, `Verified`, install method, versions and prerequisites for apps, and a `Created:` timestamp. Repository URLs are shown without any embedded credentials.

### Bulk printer tools (optional)

With the upload credential set up, two Setup entries handle many printers at once through a CSV you edit (usually in Excel). Nothing changes in Intune until you confirm a summary.

**`Printer--InTune-BulkCreate`** — publish printers from `PrinterData.json`:

1. Pick the deployment mode.
2. Choose how to start: **1** - a fresh spreadsheet export from `PrinterData.json` in Azure Blob (normal), **2** - the same from a `PrinterData.json` file on this PC, or **3** - a pre-existing sheet, to resume an earlier run. Option 3 lists your recent runs (a run's `results.csv` has only its unfinished printers ticked) and still downloads the current `PrinterData.json`, because the sheet holds only your choices while printer details always come from the JSON. If the download fails, Setup offers a local file instead.
3. For a fresh export, optionally enter default Required/Available groups to pre-fill every row (leave both blank to skip), and choose whether every printer starts ticked or none do (easier for picking a few). The sheet shows every `PrinterData.json` field (department, location, model, asset, IP, port, driver, verified, and any others) for reference. Printer details always come from the JSON itself, and the summary warns if any of those cells were edited.
4. Edit `draft.csv`. It opens in your spreadsheet program. **If this PC has none** (common on admin VMs without Office), Setup offers to install **LibreOffice** (free and open source, about 360 MB; only after you answer yes) from the public app catalog, like any other PowerDeploy app, and opens the sheet in Calc with no import dialog and every column kept as text. When saving, choose **Use Text CSV Format!**. If you decline, a basic built-in editor window is used instead, and Notepad as a last resort. Set `Include` to `N` (or delete the row) for printers you don't want, and adjust `RequiredGroups` / `AvailableGroups` (`;`-separated, same rules as the wizard). Other columns are for reference; don't change `PrinterName`. Printers that would fail to install start at `Include = N` with the reason in `Problem`.
5. Save the sheet and press Enter (in the built-in editor: **Save and continue**). Setup checks every group and every row, and lists **all** problems at once for you to fix; the built-in editor shows them above the grid when it reopens. It also finds printers that already exist in Intune **in the same deployment mode**; apps in other modes are never touched.
6. For existing printers choose **Override all**, **Skip all**, or **Decide each**. Override creates the new app first and only then backs up and deletes the old one, so the printer is never missing from Intune. The old app's install history is lost.
7. Type `yes` at the summary. Each printer is created with the same package, commands, description and notes as `Printer--InTune-Setup`. One failure doesn't stop the rest.

`results.csv` lists every printer's outcome. To retry the failures, run it again and choose **Use a pre-existing sheet**; that run is at the top of the list.

**`Printer--InTune-BulkDelete`** — clean up Intune: lists every PowerDeploy printer app (all modes) in `delete.csv` (same editor rules as above). Put `Y` in `Delete` (or tick it) for the ones to remove, save, and type the count to confirm. Each app is backed up (settings and assignments) to a JSON file before it is deleted. **Devices keep printers they already have.**

Files go to `TEMP\PrinterBulk\` in the PowerDeploy working directory. Renaming printers isn't supported yet: a renamed printer is created as a new one, and the old queue stays on devices.

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
        Technician creates the Win32 app in Intune —
        by hand (guided walkthrough) or automatically
        via Microsoft Graph (optional, admin workstation)
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
  - `InTuneAPI--Setup-and-Manage` — sets up, tests, rotates or removes the optional Intune upload credential, and shows the Multi-Admin Approval steps (see [Publishing to Intune automatically](#publishing-to-intune-automatically-optional)).
  - `OrganizationRegistryEntries--InTune-Setup` — generates the detection/remediation scripts that push org configuration to the registry, and can optionally also build a `.intunewin` of the remediation script.
  - `OrganizationRegistryEntries--Local-Setup` — asks the same questions as `OrganizationRegistryEntries--InTune-Setup` (no deployment mode), then writes the org configuration straight to this PC's `HKLM\SOFTWARE\PowerDeploy`, locks the key down, and reads the values back. For setting up a machine by hand when no registry remediation targets it.
  - `Printer--Convert-Vendor-DriverPack` — turns a manufacturer's driver pack into a PowerDeploy driver zip (see [Migrating from a print server](#migrating-from-a-print-server)).
  - `Printer--InTune-BulkCreate` / `Printer--InTune-BulkDelete` — create many printers in Intune from `PrinterData.json`, or delete many printer apps, through one CSV (see [Bulk printer tools](#bulk-printer-tools-optional)).
  - `Printer--InTune-Setup` — packages a printer from `PrinterData.json` for Intune, then walks you through creating it or creates it automatically.
  - `Printer--Install-Local` / `Printer--Uninstall-Local` — installs or removes a printer on this machine.
  - `WindowsApp--InTune-Setup` — packages an app from the catalog for Intune (not `Custom_Script` apps yet), then walks you through creating it or creates it automatically.
  - `WindowsApp--Install-Local` — installs a catalog app on this machine.
  - `WindowsApp--Uninstall-Local` — opens a sub-menu of search-and-uninstall methods for this machine: `AppPackage`, `CIM`, and `Registry`.
- [`Generate_Install-Command.ps1`](Other_Tools/Generate_Install-Command.ps1) — builds the Base64-encoded Intune install/uninstall commands and detection scripts.
- [`Security_Manager.ps1`](Other_Tools/Security_Manager.ps1) — enforces strict ACLs on PowerDeploy folders and registry.
- [`Upload-InTuneWin32App.ps1`](Other_Tools/Upload-InTuneWin32App.ps1), [`InTune-GraphAPI_Helpers.ps1`](Other_Tools/InTune-GraphAPI_Helpers.ps1), [`Get-WinGetAppDescription.ps1`](Other_Tools/Get-WinGetAppDescription.ps1) — the optional Intune upload: uploader, Graph/credential library, and the WinGet description lookup (`winget show` only; it installs nothing, but does accept WinGet's source agreements on the workstation). Tested offline by [`Tests/IntuneGraphUpload.Tests.ps1`](Tests/IntuneGraphUpload.Tests.ps1) (Windows PowerShell 5.1 and PowerShell 7).
- [`Printer-Intune_Helpers.ps1`](Other_Tools/Printer-Intune_Helpers.ps1), [`Printer-IntuneBulk.ps1`](Other_Tools/Printer-IntuneBulk.ps1), [`CsvGrid-Editor_Helpers.ps1`](Other_Tools/CsvGrid-Editor_Helpers.ps1) — the printer name/description/notes builders shared by the printer wizard and the bulk tools, the bulk tools' logic, and the built-in sheet editor used when no program opens `.csv` files. Tested offline by [`Tests/PrinterIntuneBulk.Tests.ps1`](Tests/PrinterIntuneBulk.Tests.ps1).
- Print-server migration tools — [`Export-PrinterServer-CSV.ps1`](Other_Tools/Export-PrinterServer-CSV.ps1), [`Convert-PrinterCSV-ToJSON.ps1`](Other_Tools/Convert-PrinterCSV-ToJSON.ps1), [`Export-PrinterServer-Drivers.ps1`](Other_Tools/Export-PrinterServer-Drivers.ps1), and [`Convert-VendorPack-ToDriverZip.ps1`](Other_Tools/Convert-VendorPack-ToDriverZip.ps1). See below.

### Migrating from a print server

> **Untested:** `Export-PrinterServer-CSV.ps1`, `Convert-PrinterCSV-ToJSON.ps1` and `Export-PrinterServer-Drivers.ps1` have not been validated end to end yet (export → convert → install). Review every output by hand. The printer installer refuses duplicate `PrinterName` entries, so check converted output for them.

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
| `Other_Logs` | `Convert-VendorPack-ToDriverZip.ps1`, `Generate_Custom-Script_FromTemplate.ps1`, `Upload-InTuneWin32App.ps1` when run directly with `-File` (inside the wizards the uploader writes no log of its own; `Setup_Logs` records the review, the outcome, the new app's ID, and any failure or cleanup message) |
| `Repair_Logs` | `General_Windows-Fixer.ps1` |

The print-server migration tools `Export-PrinterServer-CSV.ps1`, `Convert-PrinterCSV-ToJSON.ps1`, and `Export-PrinterServer-Drivers.ps1` write to the console only — they don't create log files.

Each entry is timestamped and tagged with a severity level (`INFO`, `WARNING`, `ERROR`, `SUCCESS`) and color-coded in the console. Because everything lands in a predictable, per-area location, troubleshooting a failed deployment is reading one log rather than correlating across the Intune Management Extension logs.

---

## Security

- **Runs in SYSTEM context** on managed endpoints, with the working directory under `C:\ProgramData` (not visible to standard users by default).
- **ACL enforcement** via the Security Manager: working folders, the Intune Management Extension log folder (`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`), and the `HKLM\SOFTWARE\PowerDeploy` hive are restricted to SYSTEM + Administrators, with inheritance broken.
- **Path validation** guards against malformed/injection-prone paths before any file or registry operation runs.
- **Azure Blob access** uses scoped, read-only SAS tokens (or AAD for user-context scenarios) rather than embedded account keys.
- **Endpoints hold no tenant credentials.** The only PowerDeploy credential that can change Intune is the optional upload secret, which lives on an admin workstation only, DPAPI-encrypted for one Windows account, and expires (default 180 days). Its permissions cover Intune apps (including app configuration and protection policies) and reading all groups and their members — protect that workstation and account accordingly, and remove the secret from PCs that no longer need it. Entra administrators who can manage the app registration can also issue new secrets for it. See [ARCHITECTURE.md §7](ARCHITECTURE.md#7-trust-and-security-model).

---

## Getting started

> High-level only — assumes Intune + an Azure Storage account.

**Before you run `Setup.ps1`:**

- **Run it as administrator** (or run `Setup_RUNNER.bat` as administrator). It uses Windows PowerShell 5.1 (`powershell.exe`), which is built into Windows.
- **To test WinGet installs locally, run it as the logged-in user who is also an administrator.** WinGet won't work properly otherwise, and Setup warns you. You can still use Setup to package apps for Intune either way.
- **Keep it in the standard location.** Setup expects its repo folder to sit inside a `C:\ProgramData\PowerDeploy…` folder. If it's anywhere else, it warns that it will lock down (restrict to SYSTEM + Administrators) the `Temp` and `Logs` folders in the repo's parent folder, and the repo folder itself — then waits for you to press Enter to continue.

1. **Fork** this repo into your organization's private repo (for production use).
2. **Stand up Azure Blob Storage**: containers for application payloads and printer drivers, plus your private `ApplicationData.json` / `PrinterData.json`.
3. **Generate and deploy the config remediation** from `Setup.ps1` (`OrganizationRegistryEntries--InTune-Setup`) to populate `HKLM\SOFTWARE\PowerDeploy` on your fleet. The wizard only asks for four values: your private repo URL, the repo token, and the printer and application container SAS keys. The other three are fixed defaults in the `OrgRegistryChangesString` function of [`Other_Tools/Generate_Install-Command.ps1`](Other_Tools/Generate_Install-Command.ps1): `StorageAccountName` = `powerdeploy`, `PrinterDataJSONpath` = `printers/PrinterData.json`, and `ApplicationDataJSONpath` = `applications/ApplicationData.json`. **If your storage account name, container names, or manifest paths are different, edit those defaults (in your private fork) before generating the scripts.** To set up a single machine by hand instead — one no remediation targets yet — use `OrganizationRegistryEntries--Local-Setup`: same questions and defaults, written straight to that PC's registry.
4. **Run `Setup.ps1` as an administrator** and follow a wizard to add an app or printer: it can test the install locally, then produce the `.intunewin`, the install/uninstall commands, and the detection script. (`Custom_Script` apps can't be packaged by the wizard yet — see [Packaging and managing your assets](#packaging-and-managing-your-assets).)
5. **Create the Win32 app in Intune** using those generated artifacts, and assign it — by hand from the guided walkthrough, or let Setup do it (optional; set up once with `InTuneAPI--Setup-and-Manage`, see [Publishing to Intune automatically](#publishing-to-intune-automatically-optional)).

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
