# NetSecure Pro

NetSecure Pro is a Python desktop application for local network supervision, security analysis, and reporting. It helps administrators discover connected hosts, inspect exposed services, monitor traffic, review alerts, calculate a security score, and generate professional PDF reports from a single interface.

## Features

- Local authentication with SQLite
- Network discovery with `Ping`, `ARP`, and TCP fallback
- Host enrichment with IP, MAC, hostname, vendor, device type, and OS guess
- Multi-mode TCP port analysis with basic banner grabbing
- Real-time network monitoring and traffic indicators
- Alerting and rule-based security scoring
- Network topology view
- Scan history, event log, and CSV export
- PDF report generation
- OpenRouter-powered AI assistant

## Screenshots

### Dashboard

![NetSecure Pro Dashboard](assets/screenshots/dashboard.png)

### Settings

![NetSecure Pro Settings](assets/screenshots/settings.png)

## Tech Stack

- Python 3.10+
- PyQt6
- SQLite
- psutil

## Getting Started

```powershell
python -m pip install -r requirements.txt
python main.py
```

## Default Credentials

- Username: `admin`
- Password: `admin123`

## Project Structure

```text
main.py
netsecure_pro/
  app.py
  auth.py
  database.py
  network.py
  ports.py
  monitor.py
  security.py
  reporting.py
  ai_assistant.py
  ui.py
```

## Notes

- Network discovery depends on local permissions, ICMP behavior, and ARP visibility on the target network.
- The application creates `netsecure_pro.db` on first launch to store users, settings, alerts, reports, and scan history.
- Generated reports and exports are kept locally and are not tracked in Git by default.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
