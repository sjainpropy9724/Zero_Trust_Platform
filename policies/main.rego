package main

import future.keywords.if
import future.keywords.in

# By default, deny
default allow := false

# --- CONFIGURATION ---
trusted_networks := {"127.0.0.1", "localhost", "172.18.0.1", "::1"}
work_hours_start := 0
work_hours_end := 24
clearance_levels := {"intern": 1, "employee": 2, "manager": 3, "admin": 4}
sensitivity_requirements := {"Clean": 1, "Public": 1, "Internal": 2, "Confidential": 3, "Restricted": 4}

# --- RULE 1: SUPER ADMIN BYPASS (The Fix) ---
# If this is true, OPA stops here and returns allow=true immediately.
allow if input.user_role == "admin"
allow if input.user_permission == "OWNER"

# --- RULE 2: STANDARD USER ACCESS ---
# Only evaluated if Rule 1 didn't already allow it.
allow if {
    input.user_role != "admin"  # Explicitly exclude admin from this complex check
    input.user_permission != "OWNER"
    is_network_trusted
    is_working_hours
    has_sufficient_clearance
    has_valid_permission
}

# --- HELPER RULES ---
is_network_trusted if input.ip_address in trusted_networks
is_working_hours if {
    input.current_hour >= work_hours_start
    input.current_hour < work_hours_end
}
has_sufficient_clearance if {
    user_level := clearance_levels[input.user_role]
    required_level := sensitivity_requirements[input.resource_sensitivity]
    user_level >= required_level
}
# Owner always has permission
has_valid_permission if input.user_permission == "OWNER"
# Download needs explicit download
has_valid_permission if {
    input.action == "download"
    input.user_permission == "download"
}
# Read needs view OR download
has_valid_permission if {
    input.action == "read"
    input.user_permission in {"view", "download"}
}

# --- DEBUG REASONS (Only populate if NOT admin) ---
deny_reasons contains "Untrusted network" if { input.user_role != "admin"; not is_network_trusted }
deny_reasons contains "Outside working hours" if { input.user_role != "admin"; not is_working_hours }
deny_reasons contains "Insufficient clearance" if { input.user_role != "admin"; not has_sufficient_clearance }
deny_reasons contains "Insufficient permission" if { input.user_role != "admin"; not has_valid_permission }