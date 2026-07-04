# Sample 1: Ransomware-like Shadow Copy Deletion
WIN_VSS_DELETE = {
    "event_category": "process",
    "event_type": "creation",
    "log_source": "windows_event_security",
    "host": {"hostname": "WS-OFFICE-01", "os_family": "windows"},
    "user": {"name": "local_admin", "domain": "WORKGROUP"},
    "process": {
        "pid": 4512,
        "name": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
        "parent_name": "cmd.exe"
    },
    "raw_log": "Process Creation: vssadmin.exe delete shadows /all /quiet"
}

# Sample 2: Encoded PowerShell (Obfuscation)
WIN_ENCODED_PS = {
    "event_category": "process",
    "event_type": "creation",
    "log_source": "powershell",
    "host": {"hostname": "WS-OFFICE-01"},
    "user": {"name": "j.doe"},
    "process": {
        "pid": 8821,
        "name": "powershell.exe",
        "command_line": "powershell.exe -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA"
    },
    "raw_log": "PowerShell Script Block Execution: Encoded Command detected"
}
# (8 more realistic samples including 4625 brute force, 4769 Kerberoasting, etc.)