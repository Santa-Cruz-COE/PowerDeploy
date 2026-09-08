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

- **A catalog, not a pile of one-off packages.** Every app and printer is a single entry in a JSON manifest. Add an entry and a guided wizard builds the Intune Win32 package, the install/uninstall commands, and the detection script for you — after letting you test the install on a real machine first.
- **Payloads are pulled at run time, not shipped through Intune.** Intune carries only a small runner. The actual installers come from WinGet or your Azure Blob Storage, and the deployment scripts come from Git, at the moment the endpoint runs. That removes Intune's package-size ceiling, and changing how something deploys means editing a script or one line of JSON — never re-wrapping and re-uploading an app.

It runs **both with and without the Company Portal**: the same definition is available as an assigned / self-service app in Intune *and* runnable on demand by a technician directly on the device.

Built for teams that have gone cloud-first and hit the walls — apps that fail to install at scale, printers that Microsoft's own cloud service can't actually deploy, and a packaging cycle measured in hours per change.

---

## Table of contents

- [The problem it solves](#the-problem-it-solves)
- [Printing: solving what Universal Print can't](#printing-solving-what-universal-print-cant)
- [Packaging and managing your assets](#packaging-and-managing-your-assets)
- [What you can do with it](#what-you-can-do-with-it)
- [How it works (under the hood)](#how-it-works-under-the-hood)
  - [The runner pattern](#the-runner-pattern)
  - [End-to-end flow](#end-to-end-flow)
  - [Where things live: scripts vs. payloads vs. config](#where-things-live-scripts-vs-payloads-vs-config)
- [With and without the Company Portal](#with-and-without-the-company-portal)
- [Components](#components)
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
| **Logging is scattered and vague.** | Every script writes structured, timestamped, severity-tagged logs to a predictable location under `C:\ProgramData`. |
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

---

## Packaging and managing your assets

Most of the recurring cost of fleet deployment isn't the install itself — it's the **packaging** and the **ongoing upkeep**. PowerDeploy is built to make both cheap, and that's the core of what it offers.

**Packaging is a guided, minutes-long task.** Run [`Setup.ps1`](Setup.ps1), pick (or define) an app or printer, and the wizard:

- optionally **test-installs it on the local machine first**, so you validate the configuration before you ship it;
- builds the **`.intunewin` package** (wrapping the runner) for you — no manual `IntuneWinAppUtil` runs;
- generates the **install command, uninstall command, and detection script**, with parameters Base64-encoded for clean Intune compatibility — no hand-writing detection logic or guessing silent-install switches;
- prints exactly what to paste into each field of the Intune Win32 app form.

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
- **Push organization configuration** (storage account, container keys, repo settings) to endpoints via Intune remediation scripts.
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

1. **Ensures Git is present** — installs Git for Windows if missing, guarded by a named mutex so parallel deployments don't collide.
2. **Clones or pulls** the target repo into the working directory (e.g. `C:\ProgramData\PowerDeploy--<mode>\PowerDeploy-Repo`), stashing any local drift first.
3. **Decodes its parameters** — Intune-friendly Base64-encoded JSON is decoded into a normal PowerShell parameter string.
4. **Locks down permissions** — runs [`Security_Manager.ps1`](Other_Tools/Security_Manager.ps1) to enforce strict ACLs (SYSTEM + Administrators only) on the working folders and the `HKLM\SOFTWARE\PowerDeploy` registry hive.
5. **Invokes the target script** (an installer, uninstaller, printer install, etc.) with the decoded parameters, capturing every line of output.
6. **Logs and exits** with a meaningful exit code that Intune can act on.

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
        ├─ install Git (mutex-guarded) → clone/pull repo
        ├─ decode Base64 params
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
| **What to install (manifest)** | `ApplicationData.json` / `PrinterData.json` (public copy in repo, private copy in Blob) | Read at run time |
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
- [`ApplicationData_TEMPLATE.json`](Templates/ApplicationData_TEMPLATE.json) / [`PrinterData_TEMPLATE.json`](Templates/PrinterData_TEMPLATE.json) — manifest formats.

**Tooling:**

- [`Setup.ps1`](Setup.ps1) — the technician's main entry point (guided wizards + local install/uninstall + config remediation generation).
- [`Generate_Install-Command.ps1`](Other_Tools/Generate_Install-Command.ps1) — builds the Base64-encoded Intune install/uninstall commands and detection scripts.
- [`Security_Manager.ps1`](Other_Tools/Security_Manager.ps1) — enforces strict ACLs on PowerDeploy folders and registry.

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
├─ Other_Tools/               # Install-command generator, Security Manager, utilities
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

**JSON manifests** describe *what* is available to deploy. Apps come from two manifests merged at run time: a **public** `ApplicationData.json` in this repo (community-maintained) and a **private** copy in your Azure Blob (your org's custom/proprietary apps). Each entry declares an `InstallMethod` (`WinGet`, `MSI-Private-AzureBlob`, `EXE-Private-AzureBlob`, `URL_Download`, `Custom_Script`) plus the fields that method needs, and optional `PreRequisites`.

---

## Deployment modes (public vs. private fork)

PowerDeploy is meant to be **forked into a private organization repo**. The public repo carries shared logic and the community app catalog; your private fork carries your org's customizations and is what production endpoints pull from.

`Setup.ps1` asks which **deployment mode** an artifact should target, which selects the repo + branch the generated package will pull from at run time:

- **Public – Development / Testing** — the official public repo (`dev` / `main`), for trying shared code.
- **Private – Development** — your fork's `dev` branch, for testing your own changes.
- **Production** — your fork's `main` branch; this is the mode for real deployments.

Each mode installs into its own `C:\ProgramData\PowerDeploy--<mode>` working directory so test and production payloads stay isolated on the same machine.

> Detailed setup of the private fork, Azure Blob containers, and SAS/AAD configuration is intended to be documented separately as the project matures.

---

## Logging

Every script writes structured logs under the working directory, e.g. `C:\ProgramData\PowerDeploy--<mode>\Logs\`, split by area (`Git_Logs`, `Installer_Logs`, `Detection_Logs`, `Config_Logs`, `Setup_Logs`). Each entry is timestamped and tagged with a severity level (`INFO`, `WARNING`, `ERROR`, `SUCCESS`) and color-coded in the console. Because everything lands in a predictable, per-area location, troubleshooting a failed deployment is reading one log rather than correlating across the Intune Management Extension logs.

---

## Security

- **Runs in SYSTEM context** on managed endpoints, with the working directory under `C:\ProgramData` (not visible to standard users by default).
- **ACL enforcement** via the Security Manager: working folders and the `HKLM\SOFTWARE\PowerDeploy` hive are restricted to SYSTEM + Administrators, with inheritance broken.
- **Path validation** guards against malformed/injection-prone paths before any file or registry operation runs.
- **Azure Blob access** uses scoped, read-only SAS tokens (or AAD for user-context scenarios) rather than embedded account keys.

---

## Getting started

> High-level only — assumes Intune + an Azure Storage account.

1. **Fork** this repo into your organization's private repo (for production use).
2. **Stand up Azure Blob Storage**: containers for application payloads and printer drivers, plus your private `ApplicationData.json` / `PrinterData.json`.
3. **Generate and deploy the config remediation** from `Setup.ps1` to populate `HKLM\SOFTWARE\PowerDeploy` on your fleet (storage account, SAS keys, JSON paths, repo URL).
4. **Run `Setup.ps1` as an administrator** and follow a wizard to add an app or printer: it can test the install locally, then produce the `.intunewin`, the install/uninstall commands, and the detection script.
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
