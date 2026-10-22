# from fastapi import FastAPI, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from datetime import datetime, timedelta, timezone
# from typing import Optional, List
# from fastapi.responses import FileResponse
# from fastapi.staticfiles import StaticFiles  # <-- ADD THIS IMPORT
# import os


# app = FastAPI(
#     title="AEGIS Security Event Correlator API",
#     description="Backend engine for processing authentication logs and correlating threat events.",
#     version="1.0.0"
# )

# # --- Enable CORS (Cross-Origin Resource Sharing) ---
# # Allows your index.html file in the browser to talk to http://127.0.0.1:8000
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )



# # --- In-Memory Database Stores (MVP) ---
# logs_db = []
# alerts_db = []

# # --- Correlation Engine Rules / Thresholds ---
# MAX_FAILED_ATTEMPTS = 3
# TIME_WINDOW_MINUTES = 5

# # Sample valid accounts database
# VALID_USERS = {
#     # "alice": "password123",
#     # "bob": "securepass456",
#     # "admin": "admin2026",
#     "tonye" : "pass123",
#     "precious": "asdfgh123",
#     "princewill": "password1234"
# }

# # --- Pydantic Request & Data Models ---
# class LoginRequest(BaseModel):
#     username: str
#     password: str
#     ip_address: Optional[str] = "192.168.1.100"
#     location: Optional[str] = "Port Harcourt, NG"

# class LogEntry(BaseModel):
#     id: int
#     timestamp: str
#     username: str
#     status: str  # "SUCCESS" or "FAILURE"
#     ip_address: str
#     location: str

# class AlertEntry(BaseModel):
#     id: int
#     title: str
#     severity: str  # "CRITICAL", "HIGH", "MEDIUM"
#     username: str
#     timestamp: str
#     description: str
#     status: str  # "ACTIVE" or "RESOLVED"


# # --- Security Event Correlation Engine Logic ---
# def correlate_events(new_log: dict):
#     """
#     Analyzes incoming authentication logs over a sliding time window.
#     Triggers a Brute-Force alert if failed attempts exceed threshold within window.
#     """
#     if new_log["status"] == "FAILURE":
#         username = new_log["username"]
#         now = datetime.fromisoformat(new_log["timestamp"])
#         window_start = now - timedelta(minutes=TIME_WINDOW_MINUTES)

#         # Count recent failures for this specific user within 5 minutes
#         recent_failures = [
#             log for log in logs_db
#             if log["username"] == username
#             and log["status"] == "FAILURE"
#             and datetime.fromisoformat(log["timestamp"]) >= window_start
#         ]

#         if len(recent_failures) >= MAX_FAILED_ATTEMPTS:
#             # Prevent duplicate active alerts for the same user
#             existing_active_alert = any(
#                 a for a in alerts_db 
#                 if a["username"] == username and a["status"] == "ACTIVE"
#             )
            
#             if not existing_active_alert:
#                 alert = {
#                     "id": len(alerts_db) + 1,
#                     "title": "Brute-Force Attack Detected",
#                     "severity": "CRITICAL",
#                     "username": username,
#                     "timestamp": datetime.now(timezone.utc).isoformat(),
#                     "description": f"User '{username}' triggered {len(recent_failures)} failed login attempts within {TIME_WINDOW_MINUTES} minutes.",
#                     "status": "ACTIVE"
#                 }
#                 alerts_db.append(alert)


# # --- API Endpoints ---
# app.mount("/", StaticFiles(directory=".", html=True), name="static")
# @app.get("/")
# def health_check():
#     """Health check endpoint to verify the API server is online."""
#     return FileResponse('index.html')
# # {"status": "online", "system": "AEGIS Security Event Correlator"}


# @app.post("/api/login")
# def login(request: LoginRequest):
#     """
#     Handles authentication requests from the Login Portal.
#     Validates credentials, logs the result, and feeds the correlation engine.
#     """
#     now_iso = datetime.now(timezone.utc).isoformat()
    
#     # Check credentials
#     if request.username in VALID_USERS and VALID_USERS[request.username] == request.password:
#         status = "SUCCESS"
#         message = f"User '{request.username}' authenticated successfully."
#     else:
#         status = "FAILURE"
#         message = f"Invalid credentials for user '{request.username}'."

#     # Record log entry
#     log_entry = {
#         "id": len(logs_db) + 1,
#         "timestamp": now_iso,
#         "username": request.username,
#         "status": status,
#         "ip_address": request.ip_address,
#         "location": request.location
#     }
#     logs_db.append(log_entry)

#     # Trigger threat detection check
#     correlate_events(log_entry)

#     return {
#         "status": status,
#         "message": message,
#         "log": log_entry
#     }


# @app.get("/api/logs")
# def get_logs():
#     """Retrieves all authentication logs sorted by newest first."""
#     return {
#         "total": len(logs_db),
#         "logs": list(reversed(logs_db))
#     }


# @app.get("/api/alerts")
# def get_alerts():
#     """Retrieves all triggered security threat alerts."""
#     return {
#         "total": len(alerts_db),
#         "alerts": list(reversed(alerts_db))
#     }


# @app.post("/api/clear")
# def clear_memory():
#     """Resets memory state (clears logs and alerts) for demo testing."""
#     global logs_db, alerts_db
#     logs_db = []
#     alerts_db = []
#     return {"status": "success", "message": "All log and alert data cleared."}



from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi.responses import FileResponse
import os

app = FastAPI(
    title="AEGIS Security Event Correlator API",
    description="Backend engine for processing authentication logs and correlating threat events.",
    version="1.0.0"
)

# --- Enable CORS (Cross-Origin Resource Sharing) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- In-Memory Database Stores (MVP) ---
logs_db = []
alerts_db = []

# --- Correlation Engine Rules / Thresholds ---
MAX_FAILED_ATTEMPTS = 3
TIME_WINDOW_MINUTES = 5

# Sample valid accounts database
VALID_USERS = {
    "tonye" : "pass123",
    "precious": "asdfgh123",
    "princewill": "password1234"
}

# --- Pydantic Request & Data Models ---
class LoginRequest(BaseModel):
    username: str
    password: str
    ip_address: Optional[str] = "192.168.1.100"
    location: Optional[str] = "Port Harcourt, NG"

class LogEntry(BaseModel):
    id: int
    timestamp: str
    username: str
    status: str  # "SUCCESS" or "FAILURE"
    ip_address: str
    location: str

class AlertEntry(BaseModel):
    id: int
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    username: str
    timestamp: str
    description: str
    status: str  # "ACTIVE" or "RESOLVED"


# --- Security Event Correlation Engine Logic ---
def correlate_events(new_log: dict):
    """
    Analyzes incoming authentication logs over a sliding time window.
    Triggers a Brute-Force alert if failed attempts exceed threshold within window.
    """
    if new_log["status"] == "FAILURE":
        username = new_log["username"]
        now = datetime.fromisoformat(new_log["timestamp"])
        window_start = now - timedelta(minutes=TIME_WINDOW_MINUTES)

        # Count recent failures for this specific user within 5 minutes
        recent_failures = [
            log for log in logs_db
            if log["username"] == username
            and log["status"] == "FAILURE"
            and datetime.fromisoformat(log["timestamp"]) >= window_start
        ]

        if len(recent_failures) >= MAX_FAILED_ATTEMPTS:
            # Prevent duplicate active alerts for the same user
            existing_active_alert = any(
                a for a in alerts_db 
                if a["username"] == username and a["status"] == "ACTIVE"
            )
            
            if not existing_active_alert:
                alert = {
                    "id": len(alerts_db) + 1,
                    "title": "Brute-Force Attack Detected",
                    "severity": "CRITICAL",
                    "username": username,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "description": f"User '{username}' triggered {len(recent_failures)} failed login attempts within {TIME_WINDOW_MINUTES} minutes.",
                    "status": "ACTIVE"
                }
                alerts_db.append(alert)


# --- API Endpoints ---

@app.post("/api/login")
def login(request: LoginRequest):
    """
    Handles authentication requests from the Login Portal.
    Validates credentials, logs the result, and feeds the correlation engine.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    
    # Check credentials
    if request.username in VALID_USERS and VALID_USERS[request.username] == request.password:
        status = "SUCCESS"
        message = f"User '{request.username}' authenticated successfully."
    else:
        status = "FAILURE"
        message = f"Invalid credentials for user '{request.username}'."

    # Record log entry
    log_entry = {
        "id": len(logs_db) + 1,
        "timestamp": now_iso,
        "username": request.username,
        "status": status,
        "ip_address": request.ip_address,
        "location": request.location
    }
    logs_db.append(log_entry)

    # Trigger threat detection check
    correlate_events(log_entry)

    return {
        "status": status,
        "message": message,
        "log": log_entry
    }


@app.get("/api/logs")
def get_logs():
    """Retrieves all authentication logs sorted by newest first."""
    return {
        "total": len(logs_db),
        "logs": list(reversed(logs_db))
    }


@app.get("/api/alerts")
def get_alerts():
    """Retrieves all triggered security threat alerts."""
    return {
        "total": len(alerts_db),
        "alerts": list(reversed(alerts_db))
    }


@app.post("/api/clear")
def clear_memory():
    """Resets memory state (clears logs and alerts) for demo testing."""
    global logs_db, alerts_db
    logs_db = []
    alerts_db = []
    return {"status": "success", "message": "All log and alert data cleared."}


# --- Frontend User Interface Routes ---
# Keeping these routes grouped here maps your HTML pages cleanly without breaking the functional endpoints above

@app.get("/")
@app.get("/index.html")
def serve_index():
    """Serves the login portal interface cleanly."""
    return FileResponse('index.html')


@app.get("/dashboard.html")
def serve_dashboard():
    """Serves the main security event metrics dashboard."""
    return FileResponse('dashboard.html')


@app.get("/logs.html")
def serve_logs_page():
    """Serves the raw events logs viewer interface."""
    return FileResponse('logs.html')
