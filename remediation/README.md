# DISA RHEL 9 STIG Remediation Automation

Automated Ansible remediation playbooks generated from DISA Security Technical Implementation Guide (STIG) requirements for Red Hat Enterprise Linux 9.

## Overview

This directory contains production-ready Ansible roles that implement DISA STIG hardening controls for RHEL 9 systems. Each task is tagged with the specific STIG Vulnerability ID (V-number), severity category (CAT I/II/III), and mapped NIST 800-53 security control.

**STIG Version:** RHEL 9 STIG V2R2 (October 2024)  
**Source:** [DISA STIG Library](https://public.cyber.mil/stigs/downloads/)  
**Platform:** Red Hat Enterprise Linux 9.x

## Coverage Statistics

Rule IDs and severities are taken from the DISA **RHEL 9 STIG Version 2, Release 5** XCCDF (`U_RHEL_9_STIG_V2R5_Manual-xccdf.xml`). NIST SP 800-53 Rev. 5 controls are derived from each rule's CCIs via the DISA CCI list. Tasks labelled `SUPPLEMENTAL` are hardening steps with no direct V2R5 rule; they are kept for defense in depth and are not counted as STIG coverage.

| Security Domain | Role | STIG Rules | CAT I | CAT II | CAT III | Supplemental Tasks | NIST 800-53 Rev. 5 Controls |
|----------------|------|-----------|-------|--------|---------|--------------------|-----------------------------|
| Session Security | `stig_session_security` | 4 | 0 | 3 | 1 | 5 | AC-10, AC-11, AC-11(1), SC-10 |
| Authentication | `stig_authentication` | 18 | 0 | 18 | 0 | 1 | AC-7, CM-6, IA-5, IA-5(1) |
| Audit Logging | `stig_audit_logging` | 39 | 0 | 38 | 1 | 2 | AC-2(4), AU-12, AU-14(1), AU-3, AU-3(1), AU-4, AU-5, AU-5(1), AU-6(4), AU-9, SI-11 |
| SSH Hardening | `stig_ssh_hardening` | 14 | 2 | 12 | 0 | 3 | AC-12, AC-17, AC-17(2), AC-7, AC-8, CM-6, IA-2(2), IA-2(5), MA-4, MA-4(7), SC-10, SC-8, SC-8(1) |
| Filesystem | `stig_filesystem` | 17 | 0 | 17 | 0 | 2 | CM-3(5), CM-6, CM-7(2), SC-4, SI-6 |
| Kernel Hardening | `stig_kernel_hardening` | 35 | 1 | 33 | 1 | 0 | AC-17(2), CM-6, CM-7, CM-7(9), IA-3, MA-4, SC-2, SC-4, SC-8, SI-16 |
| Service Hardening | `stig_service_hardening` | 15 | 5 | 10 | 0 | 3 | AC-17(1), AC-17(9), AC-3, AC-6(10), AU-8, CM-14, CM-6, CM-7, SC-45(1) |

**Total:** 141 distinct RHEL 9 V2R5 rules addressed across 7 security domains, plus 16 supplemental tasks  
**CAT I (High):** 8 rules | **CAT II (Medium):** 130 rules | **CAT III (Low):** 3 rules

Addressing a rule in this playbook is not the same as passing it. Validate each host with an SCAP scan or STIG checklist review before recording a finding as Not a Finding.

## Quick Start

### Prerequisites

- Ansible >= 2.14
- Target hosts running RHEL 9.x
- SSH access with sudo/root privileges
- `ansible.posix` collection installed

### Installation

```bash
# Install Python dependencies (for the STIG parser)
pip install -r requirements.txt

# Install required Ansible collections
ansible-galaxy collection install ansible.posix
```

### Run Full Remediation

```bash
# Dry run (check mode) — see what would change
ansible-playbook -i inventory/hosts.yml site.yml --check --diff

# Apply all STIG remediations
ansible-playbook -i inventory/hosts.yml site.yml

# Apply only CAT I (high severity) findings
ansible-playbook -i inventory/hosts.yml site.yml --tags "cat1"

# Apply only SSH hardening
ansible-playbook -i inventory/hosts.yml site.yml --tags "ssh"

# Verify applied remediations
ansible-playbook -i inventory/hosts.yml site.yml --tags "verify"
```

### Run STIG Parser

```bash
# Parse a DISA XCCDF file and output structured JSON
python stig_parser.py /path/to/U_RHEL_9_STIG_V2R2_Manual-xccdf.xml -o rules.json

# Print summary statistics only
python stig_parser.py /path/to/U_RHEL_9_STIG_V2R2_Manual-xccdf.xml --summary
```

## Architecture

```
remediation/
├── README.md                          # This file
├── stig_parser.py                     # DISA XCCDF XML parser
├── requirements.txt                   # Python dependencies
├── site.yml                           # Master playbook (runs all roles)
├── inventory/
│   └── hosts.yml                      # Example inventory
└── roles/
    ├── stig_session_security/         # AC-11: Session locking, timeouts
    ├── stig_authentication/           # IA-5: Password quality, lockout
    ├── stig_audit_logging/            # AU-*: Auditd rules, log protection
    ├── stig_ssh_hardening/            # SC-8: FIPS crypto, access controls
    ├── stig_filesystem/               # CM-6: Permissions, integrity (AIDE)
    ├── stig_kernel_hardening/         # CM-6: Sysctl, module blacklisting
    └── stig_service_hardening/        # CM-7: Firewall, NTP, disabled services
```

## Design Principles

1. **Idempotent** — Safe to run repeatedly without side effects
2. **Tagged** — Every task includes the STIG V-number, severity, and NIST control
3. **Verifiable** — Each role includes verification tasks (`--tags verify`)
4. **Configurable** — All thresholds are in `defaults/main.yml` for easy override
5. **Atomic** — Roles can be run independently via tags
6. **Auditable** — Full traceability from STIG requirement to Ansible task

## NIST 800-53 Control Mapping

| Control Family | Controls Addressed | Role(s) |
|---------------|-------------------|---------|
| AC (Access Control) | AC-3, AC-6, AC-7, AC-8, AC-10, AC-11, AC-12, AC-17 | session_security, authentication, ssh_hardening |
| AU (Audit) | AU-2, AU-3, AU-4, AU-5, AU-9, AU-12 | audit_logging |
| CM (Configuration Mgmt) | CM-5, CM-6, CM-7 | kernel_hardening, service_hardening, filesystem |
| IA (Identification/Auth) | IA-5, IA-7, IA-11 | authentication, ssh_hardening |
| SC (System/Comms Protection) | SC-5, SC-7, SC-8, SC-10, SC-13, SC-28 | ssh_hardening, kernel_hardening |
| SI (System/Info Integrity) | SI-6, SI-7, SI-11, SI-16 | filesystem, service_hardening |
| MA (Maintenance) | MA-4 | ssh_hardening |

## Customization

Override any default value in your inventory or group_vars:

```yaml
# group_vars/rhel9_servers.yml
stig_password_minlen: 20           # Override default 15
stig_ssh_client_alive_interval: 300 # Tighter timeout
stig_firewalld_allowed_services:
  - ssh
  - https                           # Add HTTPS if needed
```

## Integration with STIG Manager

These remediation playbooks complement STIG Manager's assessment tracking:

1. **Assess** — Use STIG Manager to track current compliance status
2. **Remediate** — Run these Ansible playbooks to fix findings
3. **Verify** — Re-scan with OpenSCAP/SCC, import results back to STIG Manager
4. **Report** — Generate compliance reports from STIG Manager dashboard

## Security Notice

These playbooks modify critical system security configurations. Always:
- Test in a non-production environment first
- Run with `--check --diff` before applying
- Ensure you have console access in case SSH configuration changes lock you out
- Review the STIG documentation for any site-specific exceptions
- Document any deviations in your System Security Plan (SSP)
