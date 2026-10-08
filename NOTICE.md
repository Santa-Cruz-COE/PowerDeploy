# NOTICE

## PowerDeploy

**Copyright © 2025 Santa Cruz County Office of Education**

This product was developed by the Santa Cruz County Office of Education - Technology and Innovation Division to support endpoint management for California educational institutions.

---

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at:

> <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an **"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND**, either express or implied. See the License for the specific language governing permissions and limitations under the License.

---

## Trademark Notice

The following are trademarks of the Santa Cruz County Office of Education:

- "Santa Cruz County Office of Education"
- "Santa Cruz COE"
- Associated logos and visual identities

**This license does not grant permission to use these trademarks.**

You may **not** use these names, logos, or marks to:

- Endorse or promote products derived from this software
- Imply official affiliation with or endorsement by the Santa Cruz County Office of Education
- Create confusion about the origin or sponsorship of derivative works

If you fork or modify this project, you **must** remove or replace all references to Santa Cruz County Office of Education trademarks unless you have received prior written permission.

### Permitted Trademark Uses

You **may** use the trademarks for:

- Accurate attribution in the NOTICE file (as required by Apache 2.0)
- Factual statements about the origin of the software (e.g., "Based on PowerDeploy, originally developed by Santa Cruz COE")
- Links to the official repository

---

## Maintainer

This project is maintained by **Adrian Mandel** on behalf of the Santa Cruz County Office of Education.

| | |
|---|---|
| **Repository** | <https://github.com/Santa-Cruz-COE/PowerDeploy> |
| **Maintainer** | [@Adrian-Mandel](https://github.com/Adrian-Mandel) |
| **Organization** | [Santa Cruz County Office of Education](https://santacruzcoe.org) |

---

## Third-Party Components

PowerDeploy may include or depend on the following third-party components:

| Component | License | Use |
|-----------|---------|-----|
| WinGet | MIT | Software package management |
| Microsoft.WinGet.Client | MIT | PowerShell module for WinGet |

**Bundled in this repository:**

| Component | License | Use |
|-----------|---------|-----|
| `AdobeUninstaller.exe`, `AdobeGenuineCleaner.exe`, `Creative Cloud Uninstaller (x64).exe`, `Creative Cloud Uninstaller (x86).exe` (in `Uninstallers\Adobe_Uninstaller_Suite\`) | © Adobe; not covered by this project's license | Adobe Creative Cloud full cleanup |

**Downloaded at runtime (not bundled):**

| Component | License | Use |
|-----------|---------|-----|
| Git for Windows | GPLv2 | Installed on endpoints by the runner to clone/pull the repository |
| Microsoft App Installer (WinGet) package and Microsoft.VCLibs | Microsoft's terms | Installed on endpoints by the WinGet bootstrap when WinGet is missing |
| Microsoft Win32 Content Prep Tool (`IntuneWinAppUtil.exe`) | Microsoft's terms | Builds `.intunewin` packages on the admin workstation |
| `winget-install` (PowerShell Gallery) | Publisher's terms | Fallback WinGet bootstrap |
| `Invoke-CommandAs` (PowerShell Gallery) | Publisher's terms | Runs WinGet checks in the logged-in user's context |
| PowerShellGet / NuGet package provider | Microsoft's terms | Required to install the PowerShell Gallery modules above |
| Az.Accounts / Az.Storage | Microsoft's terms | Entra-auth blob downloader prototype only |
| Office Deployment Tool | Microsoft's terms | Microsoft Office install recipe |

If additional third-party components are added, they will be documented here with their respective licenses.

---

## Contact

For questions about licensing, trademarks, or authorization:

- **General inquiries:** Open a GitHub issue
- **Security issues:** Open a GitHub issue
- **Trademark permissions:** Contact Santa Cruz COE directly
