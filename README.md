# NetSecure Pro

NetSecure Pro is a Python desktop application for local network monitoring, analysis, and basic security assessment.

## Included Modules

- Local authentication with SQLite
- Network discovery through ping sweep
- IP / MAC / hostname detection
- Common TCP port scanning
- Real-time network monitoring
- Simple alerts
- Security score calculation
- PDF report generation
- Scan history
- Event log
- Device search and filtering
- Persistent dark mode
- CSV export for key datasets
- Simplified network topology view
- Customizable security thresholds
- Multi-mode port scanning (`quick`, `common`, `extended`, `custom`)
- Basic banner grabbing for selected services
- Multi-method network scanning (`Ping`, `ARP`, `TCP fallback`)
- Enriched discovery results with vendor and discovery method
- Basic heuristic OS fingerprinting (`Windows`, `Linux`, `Router`, `Android`, `iOS`, etc.)
- Live progress bar during network scans
- Service-based fingerprint refinement after port scans
- Network scan and port scan cancellation
- Device-type icons in the topology view

## Stack

- Python 3.10+
- PyQt6
- SQLite
- psutil

## Run the Project

```powershell
python -m pip install -r requirements.txt
python main.py
```

## Default Credentials

- Username: `admin`
- Password: `admin123`

## Notes

- Network scanning relies on `ping` and `arp`, so some results may depend on Windows permissions and ICMP behavior on the target network.
- Port scanning uses a curated list of common ports to keep the application responsive.
- The PDF generator is built into the project and does not depend on `reportlab`.
- The project automatically creates `netsecure_pro.db` on first launch to store users, history, alerts, and settings.
