# Project: NexShield UI Bug Fix

## Architecture
- **Frontend**: Single Page Application styled with a modern slate theme. Displays security dashboards, reports, and host details.
- **Backend**: Flask API (`app.py`) backed by TinyDB storing host vulnerabilities and scan footprints.
- **Communication Flow**: 
  - User clicks a host in the dashboard.
  - Frontend JavaScript (`static/js/script.js`) calls `/api/host/<ip>` to retrieve scan details.
  - Frontend parses the JSON scan footprint and renders the host details popup modal, displaying open ports count and action buttons.

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | E2E Test Suite | Create comprehensive E2E test suite covering host popup port counts and button styling. | None | IN_PROGRESS (Conv: 3a98f199-08d8-43bd-acdc-f813618631d4) |
| 2 | Port Count Fix | Fix port count display logic in host details modal (`static/js/script.js`) to exclude filtered ports from `OPEN_PORTS_DETECTED`. | None | IN_PROGRESS (Conv: 1820ffbd-baa8-4934-aaea-d53834de2920) |
| 3 | Button Theme Fix | Replace hardcoded cyberpunk green/red color declarations on modal buttons with CSS theme variables or hex codes. | None | IN_PROGRESS (Conv: 1820ffbd-baa8-4934-aaea-d53834de2920) |
| 4 | Integration & E2E Pass | Run E2E tests on the final code; verify 100% pass rate. | M1, M2, M3 | PLANNED |

## Interface Contracts
### `/api/host/<path:ip>` Response Contract
- **Method**: GET
- **Response Format**:
  ```json
  {
    "status": "complete",
    "host": "<ip>",
    "footprint": {
      "protocols": [
        {
          "protocol": "tcp",
          "ports": [
            {
              "port": 80,
              "state": "open",
              "service": "http",
              "version": "nginx 1.18.0"
            },
            {
              "port": 443,
              "state": "filtered",
              "service": "https",
              "version": "-"
            }
            {
             "protocol": 
            }
          ]
        }
      ]
    }
  }
  ```

## Code Layout
- `static/js/script.js`: Contains the frontend JavaScript that calls the host API and renders the host details modal.
- `static/css/style.css`: Contains CSS rules and theme variables (`--red`, `--green`, etc.).
- `templates/index.html`: Main dashboard template.
- `app.py`: Flask application with API endpoints.
- `tests/`: Directory containing pytest tests.
