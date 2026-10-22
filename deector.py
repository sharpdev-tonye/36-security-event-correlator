from datetime import datetime, timedelta
from typing import List, Dict
from dateutil.parser import parser
from collections import defaultdict


class SecurityDetector:
    def __init__(self):
        self.failure_threshold = 5
        self.time_window_minutes = 5
        
    def parse_logs(self, logs: List[Dict]) -> List[Dict]:
        parsed = []
        for log in logs:
            
            try:
                log_copy = log.copy()
                log_copy['timestamp'] = parsed(log['timestamp'])
                parsed.append(log_copy)
            except:
                continue
        return sorted(parsed, key=lambda x: x['timestamp'])
    
    
    def detect_repeated_failures(self, logs: List[Dict]) -> List[Dict]:
        parsed_logs = self.parse_logs(logs)
        alerts = []
        user_failures = defaultdict(list)
        
        for log in parsed_logs:
            if log['status'] == 'failed':
                user_failures[log['username']].append(log)
        
        for username, failures in user_failures.items():
            if len(failures) < self.failure_threshold:
                continue
                
            for i in range(len(failures)):
                window_start = failures[i]['timestamp']
                window_end = window_start + timedelta(minutes=self.time_window_minutes)
                count = sum(1 for f in failures[i:] if f['timestamp'] <= window_end)
                if count >= self.failure_threshold:
                    alerts.append({
                        "type": "REPEATED_FAILURES",
                        "username": username,
                        "count": count,
                        "time_window": f"{self.time_window_minutes} minutes",
                        "first_attempt": str(window_start),
                        "severity": "HIGH"
                    })
                    break
        return alerts
    
    def analyze(self, logs: List[Dict]) -> Dict:
        alerts = self.detect_repeated_failures(logs)
        return {
            "total_logs": len(logs),
            "alerts": alerts,
            "summary": f"Found {len(alerts)} security alerts"
        }
        
     