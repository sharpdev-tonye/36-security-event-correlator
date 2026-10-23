# Security Event Correlator

A small FastAPI demonstration app that records authentication attempts, detects repeated failures for a username, and displays the resulting events in a browser dashboard. The project is intended for synthetic data and local demonstrations; it is not a production authentication or security monitoring system.

## What is implemented

- A login portal at `/` and `/index.html`.
- An API that checks submitted credentials against a small in-memory demo account list and records each attempt as `SUCCESS` or `FAILURE`.
- Server-side capture of the request IP and approximate IP-based location lookup (city, region, country) for public addresses.
- Brute-force detection when a username has at least **3 failed attempts within 5 minutes**. An active alert is created once per username.
- A SOC dashboard at `/dashboard.html` with event, failure, and alert counts.
- A log explorer at `/logs.html` showing the recorded authentication events.
- An endpoint to clear in-memory logs and alerts for another demo run.

The API stores data in process memory. Logs and alerts disappear when the server restarts. `sample_logs.json` is example input data, but the current API does not load it. `deector.py` is a separate detector draft and is not used by the FastAPI application.

## Project files

| File | Purpose |
| --- | --- |
| `main.py` | FastAPI application, demo credential check, event storage, correlation rule, API and page routes |
| `index.html` | Authentication attempt form |
| `dashboard.html` | Metrics and active alert view |
| `logs.html` | Authentication event table |
| `sample_logs.json` | Example authentication event data; not loaded by the app |
| `deector.py` | Standalone detector draft; not connected to the app |
| `requirements.txt` | Python dependencies |

## Requirements

- Python 3.10 or newer
- pip

## Run locally

From the project directory, create and activate a virtual environment, then install the dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate it with:

```powershell
.venv\Scripts\Activate.ps1
```

Start the API and web server:

```bash
uvicorn main:app --reload
```

Open <http://127.0.0.1:8000/>. The interactive API documentation is available at <http://127.0.0.1:8000/docs>.

## Demo flow

1. Open the login portal and submit an attempt with any username and an incorrect password three times within five minutes. The browser does not ask for IP or location; the backend records the request IP and looks up an approximate location for public IPs.
2. Open the SOC dashboard to see the recorded events and brute-force alert.
3. Open the log explorer to inspect the attempts.
4. Use **Reset Demo Data** on the dashboard, or call the clear endpoint, to start over.

The demo accounts currently defined in `main.py` are `tonye`, `precious`, and `princewill`. Their passwords are hardcoded in source for demonstration only. Do not reuse these credentials or deploy this authentication flow for real users.

## API

### `POST /api/login`

Record an authentication attempt. `username` and `password` are required. The backend captures the request IP; location is looked up from that IP and is not supplied by the browser.

```json
{
  "username": "alice",
  "password": "incorrect"
}
```

Returns the attempt status, a message, and the recorded log entry. Invalid credentials are recorded as a normal `FAILURE` result rather than an HTTP error.

### `GET /api/logs`

Returns the total number of in-memory authentication events and the events newest first.

### `GET /api/alerts`

Returns the total number of in-memory alerts and the alerts newest first.

### `POST /api/clear`

Clears all in-memory logs and alerts. This is intended for resetting the local demo.

## Configuration and data model

There are no environment variables or external database configured in the current implementation. The failure threshold and time window are constants in `main.py` (`MAX_FAILED_ATTEMPTS` and `TIME_WINDOW_MINUTES`). A log contains an ID, UTC timestamp, username, result status, request IP address, and approximate location. An alert contains a title, severity, username, timestamp, description, and status.

Location lookup uses the free HTTPS endpoint from [ipwho.is](https://ipwhois.io/documentation), which currently allows up to 1,000 requests per day per client IP without an API key. The lookup is best effort: local/private IPs, provider errors, or a two-second timeout are recorded as `Unknown`, and do not prevent the login attempt from being recorded. IP geolocation is approximate and can be wrong, especially for VPNs, mobile networks, and corporate proxies. The provider receives the IP address being looked up. In a hosted deployment behind a reverse proxy, configure the ASGI server/hosting platform to trust only the platform's forwarded client-IP header; otherwise the logged IP may be the proxy's address and its location will be shown.

## Current limitations and next steps

- This is a local MVP. In-memory state is lost on restart and is not shared between multiple server workers.
- Demo passwords are stored in plaintext in source code. Replace the demo check with proper password hashing and a real identity store before any real use.
- CORS currently allows all origins. Restrict it to trusted origins before deployment.
- IP-derived locations are approximate and depend on the external free geolocation service and its daily quota; they are not a verified physical location.
- `deector.py` is not integrated with the API and needs repair before it can be used; the active detection rule lives in `main.py`.
- The current repository does not include an automated test suite, deployment configuration, or a deployed demo URL.
- Consider validating IP addresses and timestamps, persisting events, defining a consistent event schema, and adding tests for normal login, threshold detection, and window boundaries.

## Security note

Use only synthetic accounts and data with this project. It is an educational demonstration and lacks the controls required for production authentication, durable audit logging, and security monitoring.
