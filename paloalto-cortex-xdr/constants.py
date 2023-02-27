""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
  
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
    "Informational": "informational",
    "Unknown": "unknown"
}

status_mapping = {
    "New": "new",
    "Under Investigation": "under_investigation",
    "Resolved Threat Handled": "resolved_threat_handled",
    "Resolved Known Issue": "resolved_known_issue",
    "Resolved Duplicate": "resolved_duplicate",
    "Resolved False Positive": "resolved_false_positive",
    "Resolved Other": "resolved_other"
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
        "search_from": 0,
        "search_to": 100,
        "sort": {
            "field": "creation_time",
            "keyword": "desc"
        }
    }
}

