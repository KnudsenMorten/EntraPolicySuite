
# Entra Policy Suite

The Entra Policy Suite is a modular collection of PowerShell scripts and tools for managing Microsoft Entra ID. It includes functionality for identity reporting, user tagging, conditional access policy management, and reusable utility functions.

---

## Table of Contents

- [Identity Reporting](#identity-reporting)
- [Identity Tagging](#identity-tagging)
- [Conditional Access and Group Deployment & Management](#conditional-access-and-group-deployment--management)
- [PowerShell Functions](#powershell-functions)
- [Requirements](#requirements)
- [License](#license)

---

## Identity Reporting

This module generates identity-related reports from Microsoft Entra ID. It helps administrators analyze user data and ensure compliance or licensing accuracy.

### Files

- **`IdentityReporter.ps1`**  
  Connects to Microsoft Graph and retrieves user information such as:
  - Display names, UPNs, departments
  - Group memberships
  - License details
  - Sign-in risk or authentication methods

### Usage

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
.\IdentityReporter.ps1
```

> 📄 Modify the script to include additional attributes or filters as needed.

---

## Identity Tagging

This module applies metadata or tags to Entra ID user accounts using a CSV-based input. Useful for segmentation, automation, and policy targeting.

### Files

- **`Entra-ID-User-Tagging.ps1`** – Automates tagging based on CSV input.
- **`Identity_Tagging.csv`** – Input CSV mapping users to tags.
- **`Identity_Tagging_AccountInfo.csv`** – Output audit log showing tagging results.


### Usage

```powershell
.\Entra-ID-User-Tagging.ps1
```

> ✅ Ensure Graph API permissions allow writing to user properties.

---

## Conditional Access and Group Deployment & Management

This module helps deploy, update, and manage Conditional Access (CA) policies along with related groups, using config files for consistent rollout and enforcement.

### Files

- **`Entra-ConditionalAccess-Management.ps1`** – Main script for deploying CA policies.
- **`Entra_Policy_Suite_custom.config`** – Optional, user-customized policy set.
- **`Entra_Policy_Suite_locked.config`** – Baseline or mandatory policy definitions.

### Usage

```powershell
.\Entra-ConditionalAccess-Management.ps1
```

## PowerShell Functions

This reusable module provides helper functions used across all other scripts in the suite.

### Files

- **`EntraPolicySuite.psm1`** – Contains functions for authentication, API handling, logging, data transformation, etc.

### Usage

```powershell
Import-Module .\EntraPolicySuite.psm1
```


## Requirements

- PowerShell 5.1+ or PowerShell Core 7+
- Microsoft Graph PowerShell SDK
- Admin access to Microsoft Entra ID (Azure AD)
- Connectivity to Microsoft 365 services

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
