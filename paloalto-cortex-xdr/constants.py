"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

messages_codes = {
    400: 'Invalid input',
    401: 'Unauthorized: Invalid credentials',
    500: 'Invalid input',
    404: 'Invalid input',
    'ssl_error': 'SSL certificate validation failed',
    'timeout_error': 'The request timed out while trying to connect to the remote server. Invalid Server URL.'
}

sort_field = {
    "Modification Time": "modification_time",
    "Creation Time": "creation_time",
    "First Seen": "first_seen",
    "Last Seen": "last_seen",
    "Type": "type",
    "Category": "category",
    "Trapsversion": "trapsversion",
    "Timestamp": "timestamp",
    "Domain": "domain"
}

sort_order = {
    "Ascending": "asc",
    "Descending": "desc"
}

operator_mapping = {
    "In": "in",
    "Contains": "contains",
    "Greater Than Equal To": "gte",
    "Less Than Equal To": "lte"
}

severity_mapping = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Critical": "critical",
    "Informational": "informational",
    "Unknown": "unknown"
}

status_mapping = {
    "New": "new",
    "Under Investigation": "under_investigation",
    "Resolved Known Issue": "resolved_known_issue",
    "Resolved Duplicate": "resolved_duplicate",
    "Resolved True Positive": "resolved_true_positive",
    "Resolved False Positive": "resolved_false_positive",
    "Resolved Security Testing": "resolved_security_testing",
    "Resolved Other": "resolved_other",
    "Connected": "connected",
    "Disconnected": "disconnected",
    "Lost": "lost",
    "Uninstalled": "uninstalled",
    "None": "none",
    "Pending": "pending",
    "In Progress": "in_progress",
    "Canceled": "canceled",
    "Aborted": "aborted",
    "Pending Cancellation": "pending_cancellation",
    "Success": "success",
    "Error": "error"
}

ALERT_STATUS_MAPPING = {
    "New": "new",
    "Under Investigation": "under_investigation",
    "Resolved Auto": "resolved_auto",
    "Resolved Duplicate": "resolved_duplicate",
    "Resolved False Positive": "resolved_false_positive",
    "Resolved Known Issue": "resolved_known_issue",
    "Resolved Security Testing": "resolved_security_testing",
    "Resolved Threat Handled": "resolved_threat_handled",
    "Resolved True Positive": "resolved_true_positive",
    "Resolved Other": "resolved_other",
}


platform_mapping = {
    "Windows": "windows",
    "Linux": "linux",
    "Macos": "macos",
    "Android": "android"
}

isolate_mapping = {
    "Isolated": "isolated",
    "Unisolated": "unisolated"
}


violation_type = {
    "CD ROM": "cd-rom",
    "Disk Drive": "disk drive",
    "Floppy Disk": "floppy disk",
    "Portable Device": "portable device"
}

package_type = {
    "sh—For Linux": "sh",
    "rpm—For Linux": "rpm",
    "deb—For Linux": "deb",
    "pkg—For Mac": "pkg",
    "x86—For Windows": "x86",
    "x64—For Windows": "x64"
}

category_mapping = {
    "Status": "status",
    "Audit": "audit",
    "Monitoring": "monitoring"
}

payload = {
    "request_data": {
    }
}

REPUTATION_MAPPING = {
    "Good": "GOOD",
    "Bad": "BAD",
    "Suspicious": "SUSPICIOUS",
    "Unknown": "UNKNOWN",
    "No Reputation": "NO_REPUTATION"
}

INDICATOR_TYPE_MAPPING = {
    "Hash": "HASH",
    "IP": "IP",
    "Domain Name": "DOMAIN_NAME",
    "Filename": "FILENAME"
}