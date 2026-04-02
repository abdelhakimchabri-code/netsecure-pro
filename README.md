<h1 align="center">NetSecure Pro</h1>

<p align="center">
  Intelligent desktop application for local network supervision, security analysis, operational automation, reporting, and AI-assisted remediation guidance.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/PyQt6-Desktop_UI-41CD52?style=for-the-badge&logo=qt&logoColor=white" alt="PyQt6" />
  <img src="https://img.shields.io/badge/SQLite-Local_Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite" />
  <img src="https://img.shields.io/badge/OpenRouter-AI_Assistant-0F766E?style=for-the-badge" alt="OpenRouter AI Assistant" />
  <img src="https://img.shields.io/badge/PyInstaller-Windows_EXE-1F2937?style=for-the-badge" alt="PyInstaller" />
  <img src="https://img.shields.io/badge/License-MIT-111827?style=for-the-badge" alt="MIT License" />
</p>

## Table of Contents

- [Overview](#overview)
- [Project Highlights](#project-highlights)
- [Core Capabilities](#core-capabilities)
- [Automation and Security Controls](#automation-and-security-controls)
- [Interface Preview](#interface-preview)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
- [Build Windows EXE](#build-windows-exe)
- [Project Structure](#project-structure)
- [AI Security Copilot](#ai-security-copilot)
- [Reporting and Exports](#reporting-and-exports)
- [Operational Notes](#operational-notes)
- [Roadmap / Future Improvements](#roadmap--future-improvements)
- [License](#license)

## Overview

NetSecure Pro is a Python desktop application designed to centralize local network visibility, exposure review, live monitoring, and operator guidance in one workspace. From a single interface, an administrator can discover active hosts, inspect open services, monitor traffic, review alerts, compare scans over time, schedule automatic scans, generate professional PDF reports, export security data, and query an AI copilot for remediation guidance.

The current version goes beyond a simple scanner by combining discovery, risk scoring, scheduled operations, historical comparison, user management, and AI-assisted interpretation into one operational tool.

## Project Highlights

<table>
  <tr>
    <td width="25%" valign="top">
      <strong>Unified Security Workspace</strong><br/>
      Discovery, port analysis, monitoring, alerts, reporting, AI assistance, and settings are available from one desktop application.
    </td>
    <td width="25%" valign="top">
      <strong>Operational Automation</strong><br/>
      Scheduled network scans, scheduled PDF reports, and JSON snapshots help move the application from manual review to repeatable workflow.
    </td>
    <td width="25%" valign="top">
      <strong>Actionable Intelligence</strong><br/>
      Scan comparison, stronger risk rules, toast notifications, and remediation guidance turn raw network data into decisions.
    </td>
    <td width="25%" valign="top">
      <strong>Professional Delivery</strong><br/>
      CSV exports, PDF reports, EXE packaging support, local user management, and audit-style history make the project ready for demonstration and practical use.
    </td>
  </tr>
</table>

## Core Capabilities

### Network Discovery

- Discover active hosts through `Ping`, `ARP`, and TCP fallback methods
- Auto-detect the connected network and prefill the current IP range
- Enrich discovered assets with IP, MAC address, hostname, vendor, device type, and OS guess
- Filter and search discovered hosts directly from the interface
- Support `Quick`, `Balanced`, and `Deep` discovery workflows

### Port and Service Analysis

- Run multi-mode TCP scans: `Quick`, `Common`, `Extended`, and `Custom`
- Detect exposed services and classify their risk level
- Capture basic service banners for stronger context
- Refine device understanding from exposed services after a port scan
- Explain selected ports with purpose, risk context, and remediation guidance

### Live Monitoring and Alerting

- Track upload, download, packets, and interface activity in real time
- Visualize bandwidth history with a live chart and peak indicator
- Raise alerts for high traffic spikes and suspicious operational events
- Show toast notifications for completed scans, new critical findings, and important system events

### Historical Visibility

- Store scan history, report history, and internal event logs in SQLite
- Compare the latest scan with previous baselines to highlight changes in hosts and ports
- Summarize exposure drift for both operator review and AI-assisted analysis

### Administration and Hardening

- Manage local users with `Admin` and `Viewer` style access control
- Enforce stronger password hashing and password update workflows
- Separate company profile, AI settings, thresholds, and user management in the settings workspace
- Restrict sensitive operations for non-admin users

## Automation and Security Controls

The current release includes operational automation and stronger security decision support:

- Scheduled network scans with configurable interval and scan mode
- Scheduled PDF report generation after automatic scans
- Scheduled JSON snapshot export for offline comparison or archival workflows
- Security scoring powered by rules for weak protocols, exposed administrative services, router Telnet exposure, SMB/RDP combinations, traffic spikes, and unmanaged network growth
- Notification toasts for successful scans, critical ports, scheduled task failures, and high traffic spikes
- AI quick actions such as `Top Risks`, `Fix First`, `Explain Selected Host`, `Remediation Plan`, `Summarize Changes`, `Close Selected Port`, and `Block Selected IP`

## Interface Preview

<table>
  <tr>
    <td align="center"><strong>Dashboard</strong><br/><img src="assets/screenshots/dashboard.png" alt="Dashboard" width="440" /></td>
    <td align="center"><strong>Network Scan</strong><br/><img src="assets/screenshots/network-scan.png" alt="Network Scan" width="440" /></td>
  </tr>
  <tr>
    <td align="center"><strong>Port Analysis</strong><br/><img src="assets/screenshots/port-analysis.png" alt="Port Analysis" width="440" /></td>
    <td align="center"><strong>Live Monitoring</strong><br/><img src="assets/screenshots/live-monitoring.png" alt="Live Monitoring" width="440" /></td>
  </tr>
  <tr>
    <td align="center"><strong>Topology</strong><br/><img src="assets/screenshots/topology.png" alt="Topology" width="440" /></td>
    <td align="center"><strong>AI Assistant</strong><br/><img src="assets/screenshots/ai-assistant.png" alt="AI Assistant" width="440" /></td>
  </tr>
</table>

<details>
  <summary><strong>Additional Screens</strong></summary>
  <br/>

  <table>
    <tr>
      <td align="center"><strong>History</strong><br/><img src="assets/screenshots/history.png" alt="History" width="440" /></td>
      <td align="center"><strong>Event Log</strong><br/><img src="assets/screenshots/event-log.png" alt="Event Log" width="440" /></td>
    </tr>
    <tr>
      <td align="center"><strong>Reports</strong><br/><img src="assets/screenshots/reports.png" alt="Reports" width="440" /></td>
      <td align="center"><strong>Settings</strong><br/><img src="assets/screenshots/settings.png" alt="Settings" width="440" /></td>
    </tr>
    <tr>
      <td align="center"><strong>User Management</strong><br/><img src="assets/screenshots/user-management.png" alt="User Management" width="440" /></td>
      <td align="center"><strong>Security Workflow</strong><br/>Asset discovery, exposure review, monitoring, automated reporting, AI analysis, and history comparison are all accessible from the same desktop workspace.</td>
    </tr>
  </table>

</details>

## Architecture

- **Presentation Layer**: PyQt6 windows, forms, tables, status badges, charts, toasts, and navigation
- **Discovery and Exposure Layer**: host discovery, port scanning, service enrichment, and topology rendering
- **Security Analysis Layer**: alert generation, risk scoring, comparison summaries, recommendations, and notifications
- **Automation Layer**: scheduled scans, scheduled reports, scheduled snapshots, and runtime status management
- **Administration Layer**: authentication, local user management, settings persistence, password controls, and role-based restrictions
- **Persistence Layer**: SQLite storage for users, settings, devices, alerts, reports, snapshots, events, and history
- **AI Layer**: OpenRouter-backed copilot for general cybersecurity guidance and scan-aware remediation prompts

## Technology Stack

- `Python 3.10+`
- `PyQt6`
- `SQLite`
- `psutil`
- `OpenRouter API`
- `PyInstaller`

## Getting Started

### 1. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 2. Launch the application

```powershell
python main.py
```

### 3. Sign in with the default demo account

- Username: `admin`
- Password: `admin123`

## Build Windows EXE

The repository includes PyInstaller support for generating a distributable Windows build.

### 1. Install build dependencies

```powershell
python -m pip install -r requirements-build.txt
```

### 2. Build the application

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build_release.ps1 -Clean
```

### 3. Locate the generated executable

```text
dist\NetSecure Pro\NetSecure Pro.exe
```

Keep the full `dist\NetSecure Pro` folder together when moving the application to another Windows machine.

## Project Structure

```text
main.py
build_release.ps1
netsecure_pro.spec
requirements.txt
requirements-build.txt
netsecure_pro/
  __init__.py
  app.py
  ai_assistant.py
  auth.py
  database.py
  exports.py
  models.py
  monitor.py
  network.py
  ports.py
  reporting.py
  security.py
  ui.py
assets/screenshots/
README.md
LICENSE
```

## AI Security Copilot

The application includes an integrated AI assistant with two operating modes:

- **General Chat**: ask defensive cybersecurity questions such as how to close a port, block an IP, harden a service, or review a remediation approach
- **Scan-Aware Chat**: ask questions that rely on the latest discovered hosts, open ports, alerts, score, and comparison summary

The assistant also includes quick prompt actions for routine operator tasks:

- `Top Risks`
- `Fix First`
- `Suspicious Host`
- `Explain Selected Host`
- `Remediation Plan`
- `Summarize Changes`
- `Close Selected Port`
- `Block Selected IP`

## Reporting and Exports

The application supports multiple output formats for review and archival:

- Professional PDF security reports with executive summary, findings, and recommendations
- CSV exports from key tables and operational views
- Scheduled and on-demand JSON snapshots for structured scan retention
- History records for scans, reports, and internal events

## Operational Notes

- Network discovery depends on local permissions, ICMP behavior, ARP visibility, and the active Windows interface.
- The application creates `netsecure_pro.db` on first launch to store users, settings, alerts, reports, scan history, and automation preferences.
- Generated reports and exports stay local and are ignored by Git by default.
- The default credentials are intended for demonstration only and should be changed in real deployments.
- OpenRouter API credentials are managed from the settings page and should be protected like any operational secret.

## Roadmap / Future Improvements

### Security Intelligence

- Add richer anomaly detection workflows backed by local telemetry baselines
- Expand service fingerprinting and host classification accuracy
- Introduce more contextual remediation mapping per device profile and exposure set

### Visibility and Reporting

- Add richer diff views for scan comparison and historical exposure evolution
- Extend PDF and export outputs with deeper visual summaries and trend charts
- Improve topology insight with richer relationships and interactive drill-down behavior

### Administration and Operations

- Add stronger account lifecycle controls and broader administrative workflows
- Improve secret handling and configuration hardening for production-style usage
- Extend scheduled tasks with retention policies and more flexible execution rules

### Distribution

- Package the project with an installer workflow in addition to the EXE build
- Improve release automation and deployment documentation
- Explore broader integration scenarios for multi-network or client-server deployment

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
