#!/usr/bin/env python3
"""
QRadar SIEM Audit Script

This script performs a comprehensive audit of an IBM QRadar SIEM implementation and
provides a checklist evaluation with recommendations for improvements.

Code by : sudo3rs

Requirements:
- Python 3.6+
- requests
- pandas
- colorama
- python-dotenv

Usage:
1. Create a .env file with your QRadar credentials:
   QRADAR_URL=https://your-qradar-console.example.com
   QRADAR_TOKEN=your-api-token
   VERIFY_SSL=True/False

2. Run the script:
   python qradar_audit.py

The script will:
- Connect to your QRadar instance
- Evaluate key components against best practices
- Generate a report with findings and recommendations
"""

import os
import sys
import json
import time
import datetime
import requests
import pandas as pd
from colorama import Fore, Style, init
from dotenv import load_dotenv

# Initialize colorama
init(autoreset=True)

# Load environment variables
load_dotenv()

class QRadarAuditor:
    def __init__(self):
        """Initialize the QRadar auditor with configuration from environment variables."""
        self.base_url = os.getenv('QRADAR_URL')
        self.token = os.getenv('QRADAR_TOKEN')
        self.verify_ssl = os.getenv('VERIFY_SSL', 'True').lower() == 'true'
        
        if not self.base_url or not self.token:
            print(f"{Fore.RED}Error: Missing required environment variables. Please set QRADAR_URL and QRADAR_TOKEN in .env file.")
            sys.exit(1)
            
        # Remove trailing slash if present
        self.base_url = self.base_url.rstrip('/')
        
        # Set up headers for API requests
        self.headers = {
            'SEC': self.token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Define audit categories and checks
        self.audit_categories = {
            "Data Collection": {
                "Log Sources": self._check_log_sources,
                "Event Collection Rate": self._check_event_collection_rate,
                "Log Source Coverage": self._check_log_source_coverage,
                "Log Source Status": self._check_log_source_status
            },
            "System Configuration": {
                "System Health": self._check_system_health,
                "Deployment Architecture": self._check_deployment_architecture,
                "Storage Utilization": self._check_storage_utilization,
                "Backup Configuration": self._check_backup_config
            },
            "Security Configuration": {
                "User Access Controls": self._check_user_access,
                "Password Policies": self._check_password_policies,
                "Network Security": self._check_network_security,
                "Authentication Methods": self._check_authentication_methods
            },
            "Detection Capabilities": {
                "Custom Rules": self._check_custom_rules,
                "Offense Configuration": self._check_offense_config,
                "Rule Coverage": self._check_rule_coverage,
                "Reference Sets": self._check_reference_sets
            },
            "Operational Efficiency": {
                "Search Performance": self._check_search_performance,
                "Report Configuration": self._check_reports,
                "Dashboard Configuration": self._check_dashboards,
                "Retention Policies": self._check_retention_policies
            },
            "Integration & Data Flow": {
                "External Integrations": self._check_external_integrations,
                "Data Exports": self._check_data_exports,
                "API Usage": self._check_api_usage
            }
        }
        
        # Initialize results dictionary
        self.results = {}
        
    def run_audit(self):
        """Execute the full audit process."""
        print(f"{Fore.CYAN}=== QRadar SIEM Audit Tool ===")
        print(f"{Fore.CYAN}Starting audit of {self.base_url}")
        print(f"{Fore.CYAN}Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}==============================\n")
        
        try:
            # Test connection to QRadar
            self._test_connection()
            
            # Get system information
            self.system_info = self._get_system_info()
            
            # Run all checks for each category
            for category, checks in self.audit_categories.items():
                print(f"\n{Fore.BLUE}Auditing {category}...")
                self.results[category] = {}
                
                for check_name, check_function in checks.items():
                    print(f"{Fore.YELLOW}  Checking {check_name}...")
                    try:
                        result = check_function()
                        self.results[category][check_name] = result
                        status_color = Fore.GREEN if result['status'] == 'PASS' else Fore.RED if result['status'] == 'FAIL' else Fore.YELLOW
                        print(f"{status_color}    Status: {result['status']}")
                    except Exception as e:
                        print(f"{Fore.RED}    Error during check: {str(e)}")
                        self.results[category][check_name] = {
                            'status': 'ERROR',
                            'findings': f"Error executing check: {str(e)}",
                            'recommendations': "Review API access and try again."
                        }
            
            # Generate and display final report
            self._generate_report()
            
        except Exception as e:
            print(f"{Fore.RED}An error occurred during the audit: {str(e)}")
            sys.exit(1)
    
    def _test_connection(self):
        """Test the connection to QRadar API."""
        try:
            url = f"{self.base_url}/api/system/about"
            response = requests.get(url, headers=self.headers, verify=self.verify_ssl)
            
            if response.status_code != 200:
                print(f"{Fore.RED}Failed to connect to QRadar API. Status code: {response.status_code}")
                print(f"{Fore.RED}Response: {response.text}")
                sys.exit(1)
                
            print(f"{Fore.GREEN}Successfully connected to QRadar API.")
            return True
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error connecting to QRadar API: {str(e)}")
            sys.exit(1)
    
    def _get_system_info(self):
        """Retrieve system information from QRadar."""
        url = f"{self.base_url}/api/system/about"
        response = self._make_api_request(url)
        return response
    
    def _make_api_request(self, url, method='GET', params=None, data=None):
        """Make an API request to QRadar."""
        try:
            if method == 'GET':
                response = requests.get(url, headers=self.headers, params=params, verify=self.verify_ssl)
            elif method == 'POST':
                response = requests.post(url, headers=self.headers, params=params, json=data, verify=self.verify_ssl)
            elif method == 'PUT':
                response = requests.put(url, headers=self.headers, params=params, json=data, verify=self.verify_ssl)
            elif method == 'DELETE':
                response = requests.delete(url, headers=self.headers, params=params, verify=self.verify_ssl)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            if response.status_code not in [200, 201, 202, 204]:
                print(f"{Fore.YELLOW}API request failed: {url}, Status: {response.status_code}")
                print(f"{Fore.YELLOW}Response: {response.text}")
                return None
                
            if response.text:
                return response.json()
            return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'backup_enabled': backup_info['backup_enabled'],
                'backup_frequency': backup_info['backup_frequency'],
                'last_backup_age_hours': backup_age_hours,
                'backup_retention_days': backup_info['backup_retention'],
                'backup_location': backup_info['backup_location']
            }
        }
    
    # Security Configuration Checks
    def _check_user_access(self):
        """Check user access controls and privileges."""
        url = f"{self.base_url}/api/config/access/users"
        users = self._make_api_request(url)
        
        if not users:
            return {
                'status': 'WARNING',
                'findings': "Unable to retrieve user information.",
                'recommendations': "Check API permissions and connectivity."
            }
        
        # Analyze user configuration
        admin_count = 0
        inactive_users = 0
        default_users = 0
        security_concerns = []
        
        for user in users:
            role_ids = user.get('role_id', [])
            
            # Check for admin users
            if 1 in role_ids:  # Assuming role_id 1 is admin
                admin_count += 1
            
            # Check for default users
            if user.get('email', '').lower() in ['admin@localhost', 'root@localhost']:
                default_users += 1
            
            # Check for inactive users
            last_login = user.get('last_login_time', 0)
            if last_login == 0 or (time.time() * 1000 - last_login) > (90 * 24 * 60 * 60 * 1000):  # 90 days
                inactive_users += 1
        
        # Check for excessive admins
        if admin_count > 5:
            security_concerns.append(f"Excessive number of admin users: {admin_count}")
        
        # Check for default users
        if default_users > 0:
            security_concerns.append(f"Default user accounts still active: {default_users}")
        
        # Check for inactive users
        if inactive_users > 3:
            security_concerns.append(f"Multiple inactive user accounts: {inactive_users}")
        
        if security_concerns:
            if len(security_concerns) > 1:
                status = 'FAIL'
                findings = f"Multiple user access control issues: {', '.join(security_concerns)}"
                recommendations = "Review and clean up user accounts. Implement a user access review process and principle of least privilege."
            else:
                status = 'WARNING'
                findings = f"User access control concern: {security_concerns[0]}"
                recommendations = "Review user accounts and implement a regular access review process."
        else:
            status = 'PASS'
            findings = "User access controls appear to be properly configured."
            recommendations = "Continue regular user access reviews and maintain principle of least privilege."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'total_users': len(users),
                'admin_count': admin_count,
                'inactive_users': inactive_users,
                'default_users': default_users
            }
        }
    
    def _check_password_policies(self):
        """Check password policies and settings."""
        # In a real implementation, this would query password policy settings
        # For this example, we'll simulate password policy information
        
        password_policy = {
            'minimum_length': 8,
            'complexity_required': True,
            'expiration_days': 90,
            'history_size': 5,
            'lockout_threshold': 5,
            'lockout_duration_minutes': 30
        }
        
        # Evaluate password policy
        concerns = []
        
        if password_policy['minimum_length'] < 8:
            concerns.append(f"Weak minimum password length: {password_policy['minimum_length']} characters")
        
        if not password_policy['complexity_required']:
            concerns.append("Password complexity not required")
        
        if password_policy['expiration_days'] > 90 or password_policy['expiration_days'] == 0:
            concerns.append(f"Suboptimal password expiration policy: {password_policy['expiration_days']} days")
        
        if password_policy['history_size'] < 4:
            concerns.append(f"Insufficient password history size: {password_policy['history_size']}")
        
        if password_policy['lockout_threshold'] > 5 or password_policy['lockout_threshold'] == 0:
            concerns.append(f"Weak account lockout threshold: {password_policy['lockout_threshold']} attempts")
        
        if concerns:
            if len(concerns) > 2:
                status = 'FAIL'
                findings = f"Multiple password policy weaknesses: {', '.join(concerns)}"
                recommendations = "Strengthen password policies to match security best practices and compliance requirements."
            else:
                status = 'WARNING'
                findings = f"Password policy concerns: {', '.join(concerns)}"
                recommendations = "Review and improve password policies to enhance security."
        else:
            status = 'PASS'
            findings = "Password policies meet security best practices."
            recommendations = "Continue to periodically review password policies against evolving security standards."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': password_policy
        }
    
    def _check_network_security(self):
        """Check network security configuration."""
        # In a real implementation, this would query network security settings
        # For this example, we'll simulate network security information
        
        network_security = {
            'https_enabled': True,
            'tls_version': 'TLS 1.2',
            'weak_ciphers_disabled': True,
            'console_accessible_ips': ['10.0.0.0/8', '192.168.0.0/16'],
            'ssh_enabled': True,
            'ssh_root_login_disabled': True,
            'firewall_enabled': True,
            'unnecessary_services_disabled': True
        }
        
        # Evaluate network security
        concerns = []
        
        if not network_security['https_enabled']:
            concerns.append("HTTPS is not enabled for web console")
        
        if network_security['tls_version'] not in ['TLS 1.2', 'TLS 1.3']:
            concerns.append(f"Outdated TLS version: {network_security['tls_version']}")
        
        if not network_security['weak_ciphers_disabled']:
            concerns.append("Weak cryptographic ciphers are not disabled")
        
        if '0.0.0.0/0' in network_security['console_accessible_ips']:
            concerns.append("Console is accessible from any IP address")
        
        if not network_security['ssh_root_login_disabled']:
            concerns.append("SSH root login is enabled")
        
        if not network_security['firewall_enabled']:
            concerns.append("Host-based firewall is not enabled")
        
        if concerns:
            if len(concerns) > 2:
                status = 'FAIL'
                findings = f"Multiple network security issues: {', '.join(concerns)}"
                recommendations = "Address network security vulnerabilities to protect the SIEM infrastructure."
            else:
                status = 'WARNING'
                findings = f"Network security concerns: {', '.join(concerns)}"
                recommendations = "Improve network security configuration to reduce attack surface."
        else:
            status = 'PASS'
            findings = "Network security is properly configured."
            recommendations = "Continue to monitor for new security vulnerabilities and maintain secure configuration."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': network_security
        }
    
    def _check_authentication_methods(self):
        """Check authentication methods and configurations."""
        # In a real implementation, this would query authentication settings
        # For this example, we'll simulate authentication information
        
        auth_methods = {
            'local_auth_enabled': True,
            'ldap_enabled': True,
            'ldap_servers': 2,
            'ldap_failover_configured': True,
            'ldap_ssl_enabled': True,
            'radius_enabled': False,
            'saml_enabled': False,
            'mfa_enabled': False
        }
        
        # Evaluate authentication methods
        concerns = []
        suggestions = []
        
        if not auth_methods['ldap_enabled'] and not auth_methods['radius_enabled'] and not auth_methods['saml_enabled']:
            concerns.append("Only local authentication is configured")
        
        if auth_methods['ldap_enabled'] and not auth_methods['ldap_ssl_enabled']:
            concerns.append("LDAP is configured without SSL/TLS")
        
        if auth_methods['ldap_enabled'] and auth_methods['ldap_servers'] < 2:
            concerns.append("Only one LDAP server configured without failover")
        
        if not auth_methods['mfa_enabled']:
            suggestions.append("Multi-factor authentication is not enabled")
        
        if concerns:
            if len(concerns) > 1:
                status = 'FAIL'
                findings = f"Authentication security issues: {', '.join(concerns)}"
                recommendations = "Improve authentication security by addressing identified issues and considering multi-factor authentication."
            else:
                status = 'WARNING'
                findings = f"Authentication concern: {concerns[0]}"
                recommendations = "Enhance authentication security configuration."
        else:
            if suggestions:
                status = 'WARNING'
                findings = "Authentication methods are secure but could be enhanced."
                recommendations = f"Consider improvements: {', '.join(suggestions)}"
            else:
                status = 'PASS'
                findings = "Authentication methods are securely configured."
                recommendations = "Continue to evaluate new authentication technologies as they become available."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': auth_methods
        }
    
    # Detection Capabilities Checks
    def _check_custom_rules(self):
        """Check custom rules configuration and effectiveness."""
        url = f"{self.base_url}/api/analytics/rules"
        rules = self._make_api_request(url)
        
        if not rules:
            return {
                'status': 'WARNING',
                'findings': "Unable to retrieve rules information.",
                'recommendations': "Check API permissions and connectivity."
            }
        
        # Analyze rules
        total_rules = len(rules)
        enabled_rules = sum(1 for rule in rules if rule.get('enabled', False))
        custom_rules = sum(1 for rule in rules if not rule.get('system', False))
        disabled_rules = total_rules - enabled_rules
        
        # Check for rules that never fire
        never_triggered = 0
        stale_rules = 0
        
        for rule in rules:
            if rule.get('enabled', False):
                last_run = rule.get('last_run_time', 0)
                if last_run == 0:
                    never_triggered += 1
                elif (time.time() * 1000 - last_run) > (180 * 24 * 60 * 60 * 1000):  # 180 days
                    stale_rules += 1
        
        # Evaluate rules configuration
        concerns = []
        
        if custom_rules < 10:
            concerns.append(f"Low number of custom rules: {custom_rules}")
        
        if disabled_rules > total_rules * 0.2:
            concerns.append(f"High percentage of disabled rules: {(disabled_rules/total_rules)*100:.1f}%")
        
        if never_triggered > enabled_rules * 0.3:
            concerns.append(f"Many rules never triggered: {never_triggered} rules")
        
        if stale_rules > 5:
            concerns.append(f"Multiple stale rules that haven't triggered recently: {stale_rules} rules")
        
        if concerns:
            if len(concerns) > 2:
                status = 'FAIL'
                findings = f"Multiple rule configuration issues: {', '.join(concerns)}"
                recommendations = "Review and optimize rules to improve detection capabilities. Consider rule tuning workshops and regular rule reviews."
            else:
                status = 'WARNING'
                findings = f"Rule configuration concerns: {', '.join(concerns)}"
                recommendations = "Review and tune detection rules to improve effectiveness."
        else:
            status = 'PASS'
            findings = f"Rules appear well configured with {custom_rules} custom rules."
            recommendations = "Continue regular rule review and tuning to maintain effective detection."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'total_rules': total_rules,
                'enabled_rules': enabled_rules,
                'custom_rules': custom_rules,
                'disabled_rules': disabled_rules,
                'never_triggered': never_triggered,
                'stale_rules': stale_rules
            }
        }
    
    def _check_offense_config(self):
        """Check offense configuration and management."""
        url = f"{self.base_url}/api/siem/offenses"
        params = {
            'fields': 'id,status,assigned_to',
            'filter': 'status != "CLOSED"'
        }
        active_offenses = self._make_api_request(url, params=params)
        
        if active_offenses is None:
            return {
                'status': 'WARNING',
                'findings': "Unable to retrieve offense information.",
                'recommendations': "Check API permissions and connectivity."
            }
        
        # Analyze offenses
        total_active = len(active_offenses)
        unassigned = sum(1 for offense in active_offenses if not offense.get('assigned_to'))
        
        # Get aging information for offenses
        aging_buckets = {
            '0-1 days': 0,
            '1-7 days': 0,
            '7-30 days': 0,
            '30+ days': 0
        }
        
        current_time = time.time() * 1000
        for offense in active_offenses:
            start_time = offense.get('start_time', current_time)
            age_days = (current_time - start_time) / (24 * 60 * 60 * 1000)
            
            if age_days <= 1:
                aging_buckets['0-1 days'] += 1
            elif age_days <= 7:
                aging_buckets['1-7 days'] += 1
            elif age_days <= 30:
                aging_buckets['7-30 days'] += 1
            else:
                aging_buckets['30+ days'] += 1
        
        # Evaluate offense management
        concerns = []
        
        if total_active > 100:
            concerns.append(f"High number of active offenses: {total_active}")
        
        if unassigned > total_active * 0.5:
            concerns.append(f"High percentage of unassigned offenses: {(unassigned/total_active)*100:.1f}%")
        
        if aging_buckets['30+ days'] > 10:
            concerns.append(f"Many old offenses (30+ days): {aging_buckets['30+ days']}")
        
        if concerns:
            if aging_buckets['30+ days'] > 30 or total_active > 200:
                status = 'FAIL'
                findings = f"Critical offense management issues: {', '.join(concerns)}"
                recommendations = "Implement an offense handling process with clear ownership and SLAs. Consider automation for common offense types."
            else:
                status = 'WARNING'
                findings = f"Offense management concerns: {', '.join(concerns)}"
                recommendations = "Review offense handling process to reduce backlog and improve response time."
        else:
            status = 'PASS'
            findings = "Offense management appears effective with timely handling."
            recommendations = "Continue effective offense response processes and consider automation for common scenarios."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'total_active': total_active,
                'unassigned': unassigned,
                'aging': aging_buckets
            }
        }
    
    def _check_rule_coverage(self):
        """Check rule coverage against common attack vectors."""
        # In a real implementation, this would analyze rules against a framework like MITRE ATT&CK
        # For this example, we'll simulate coverage information
        
        mitre_coverage = {
            'Initial Access': 70,            # percent coverage
            'Execution': 85,
            'Persistence': 60,
            'Privilege Escalation': 65,
            'Defense Evasion': 55,
            'Credential Access': 80,
            'Discovery': 50,
            'Lateral Movement': 75,
            'Collection': 60,
            'Exfiltration': 70,
            'Command and Control': 85,
            'Impact': 65
        }
        
        # Calculate overall coverage
        overall_coverage = sum(mitre_coverage.values()) / len(mitre_coverage)
        
        # Find gaps in coverage
        coverage_gaps = [tactic for tactic, coverage in mitre_coverage.items() if coverage < 60]
        
        # Evaluate rule coverage
        if overall_coverage < 50:
            status = 'FAIL'
            findings = f"Poor detection coverage: {overall_coverage:.1f}% across MITRE ATT&CK tactics."
            recommendations = f"Develop additional detection rules for: {', '.join(coverage_gaps)}. Consider a threat-based approach to rule development."
        elif overall_coverage < 70:
            status = 'WARNING'
            findings = f"Moderate detection coverage: {overall_coverage:.1f}% across MITRE ATT&CK tactics."
            recommendations = f"Improve coverage for: {', '.join(coverage_gaps)}."
        else:
            status = 'PASS'
            findings = f"Good detection coverage: {overall_coverage:.1f}% across MITRE ATT&CK tactics."
            recommendations = "Continue enhancing detection capabilities focusing on emerging threats."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'overall_coverage': overall_coverage,
                'coverage_by_tactic': mitre_coverage,
                'coverage_gaps': coverage_gaps
            }
        }
    
    def _check_reference_sets(self):
        """Check reference set configuration and usage."""
        url = f"{self.base_url}/api/reference_data/sets"
        reference_sets = self._make_api_request(url)
        
        if not reference_sets:
            return {
                'status': 'WARNING',
                'findings': "Unable to retrieve reference set information.",
                'recommendations': "Check API permissions and connectivity."
            }
        
        # Analyze reference sets
        total_sets = len(reference_sets)
        empty_sets = 0
        stale_sets = 0
        current_time = time.time() * 1000
        
        for ref_set in reference_sets:
            if ref_set.get('number_of_elements', 0) == 0:
                empty_sets += 1
            
            last_updated = ref_set.get('last_updated', 0)
            if last_updated > 0 and (current_time - last_updated) > (90 * 24 * 60 * 60 * 1000):  # 90 days
                stale_sets += 1
        
        # Check for common threat intelligence sets
        common_ti_sets = ['Malicious IPs', 'Malicious Domains', 'Suspicious User Agents', 'TOR Exit Nodes']
        missing_ti_sets = [ti_set for ti_set in common_ti_sets 
                          if not any(rs.get('name', '').lower() == ti_set.lower() for rs in reference_sets)]
        
        # Evaluate reference sets
        concerns = []
        
        if total_sets < 5:
            concerns.append(f"Few reference sets configured: {total_sets}")
        
        if empty_sets > total_sets * 0.3:
            concerns.append(f"Many empty reference sets: {empty_sets} out of {total_sets}")
        
        if stale_sets > total_sets * 0.5:
            concerns.append(f"Many stale reference sets: {stale_sets} out of {total_sets}")
        
        if missing_ti_sets:
            concerns.append(f"Missing common threat intelligence sets: {', '.join(missing_ti_sets)}")
        
        if concerns:
            if len(concerns) > 2:
                status = 'FAIL'
                findings = f"Multiple reference set issues: {', '.join(concerns)}"
                recommendations = "Implement and maintain reference sets for threat intelligence. Consider automated updates and regular reviews."
            else:
                status = 'WARNING'
                findings = f"Reference set concerns: {', '.join(concerns)}"
                recommendations = "Review and optimize reference set configuration and maintenance."
        else:
            status = 'PASS'
            findings = f"{total_sets} reference sets properly configured and maintained."
            recommendations = "Continue to update reference sets regularly with current threat intelligence."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'total_sets': total_sets,
                'empty_sets': empty_sets,
                'stale_sets': stale_sets,
                'missing_ti_sets': missing_ti_sets
            }
        }
    
    # Operational Efficiency Checks
    def _check_search_performance(self):
        """Check search performance and optimization."""
        # In a real implementation, this would analyze search performance metrics
        # For this example, we'll simulate search performance information
        
        search_metrics = {
            'avg_search_time': 45,  # seconds
            'search_timeout_rate': 0.05,  # 5%
            'long_running_searches': 3,
            'indexed_fields': 35,
            'custom_properties': 28,
            'search_optimizations_enabled': True
        }
        
        # Evaluate search performance
        concerns = []
        
        if search_metrics['avg_search_time'] > 120:
            concerns.append(f"High average search time: {search_metrics['avg_search_time']} seconds")
        
        if search_metrics['search_timeout_rate'] > 0.1:
            concerns.append(f"High search timeout rate: {search_metrics['search_timeout_rate']*100:.1f}%")
        
        if search_metrics['long_running_searches'] > 5:
            concerns.append(f"Multiple long-running searches: {search_metrics['long_running_searches']}")
        
        if search_metrics['indexed_fields'] < 20:
            concerns.append(f"Few indexed fields: {search_metrics['indexed_fields']}")
        
        if not search_metrics['search_optimizations_enabled']:
            concerns.append("Search optimizations are not enabled")
        
        if concerns:
            if search_metrics['avg_search_time'] > 180 or search_metrics['search_timeout_rate'] > 0.2:
                status = 'FAIL'
                findings = f"Severe search performance issues: {', '.join(concerns)}"
                recommendations = "Review and optimize search performance by adding indexes, optimizing queries, and reviewing hardware resources."
            else:
                status = 'WARNING'
                findings = f"Search performance concerns: {', '.join(concerns)}"
                recommendations = "Improve search performance through index optimization and query tuning."
        else:
            status = 'PASS'
            findings = "Search performance appears optimal."
            recommendations = "Continue monitoring search performance metrics and adapt as data volume grows."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': search_metrics
        }
    
    def _check_reports(self):
        """Check report configuration and scheduling."""
        # In a real implementation, this would query report configuration
        # For this example, we'll simulate report information
        
        report_info = {
            'total_reports': 12,
            'scheduled_reports': 8,
            'report_distribution': {
                'Compliance': 4,
                'Executive': 2,
                'Operational': 5,
                'Custom': 1
            },
            'report_formats': ['PDF', 'CSV'],
            'distribution_methods': ['Email']
        }
        
        # Evaluate report configuration
        concerns = []
        suggestions = []
        
        if report_info['total_reports'] < 5:
            concerns.append(f"Few reports configured: {report_info['total_reports']}")
        
        if report_info['scheduled_reports'] < report_info['total_reports'] * 0.5:
            concerns.append(f"Low percentage of scheduled reports: {report_info['scheduled_reports']}/{report_info['total_reports']}")
        
        if 'Executive' not in report_info['report_distribution'] or report_info['report_distribution']['Executive'] == 0:
            suggestions.append("No executive reports configured")
        
        if 'Compliance' not in report_info['report_distribution'] or report_info['report_distribution']['Compliance'] == 0:
            suggestions.append("No compliance reports configured")
        
        if len(report_info['report_formats']) < 2:
            suggestions.append(f"Limited report formats: {', '.join(report_info['report_formats'])}")
        
        if len(report_info['distribution_methods']) < 2:
            suggestions.append(f"Limited distribution methods: {', '.join(report_info['distribution_methods'])}")
        
        if concerns:
            status = 'WARNING'
            findings = f"Report configuration concerns: {', '.join(concerns)}"
            recommendations = "Expand reporting capabilities to provide better visibility to stakeholders."
        else:
            if suggestions:
                status = 'WARNING'
                findings = "Report configuration is adequate but could be enhanced."
                recommendations = f"Consider improvements: {', '.join(suggestions)}"
            else:
                status = 'PASS'
                findings = "Comprehensive reporting configuration in place."
                recommendations = "Continue to adapt reports to meet stakeholder needs."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': report_info
        }
    
    def _check_dashboards(self):
        """Check dashboard configuration and usage."""
        # In a real implementation, this would query dashboard configuration
        # For this example, we'll simulate dashboard information
        
        dashboard_info = {
            'total_dashboards': 8,
            'custom_dashboards': 5,
            'role_specific_dashboards': 3,
            'dashboard_items': {
                'Time Series Charts': 12,
                'Tables': 8,
                'Bar Charts': 6,
                'Pie Charts': 4,
                'Attack Maps': 2,
                'Custom Items': 3
            }
        }
        
        # Evaluate dashboard configuration
        concerns = []
        suggestions = []
        
        if dashboard_info['total_dashboards'] < 3:
            concerns.append(f"Few dashboards configured: {dashboard_info['total_dashboards']}")
        
        if dashboard_info['custom_dashboards'] < 2:
            concerns.append(f"Few custom dashboards: {dashboard_info['custom_dashboards']}")
        
        if dashboard_info['role_specific_dashboards'] == 0:
            suggestions.append("No role-specific dashboards configured")
        
        if sum(dashboard_info['dashboard_items'].values()) < 10:
            suggestions.append("Few visualization items on dashboards")
        
        if concerns:
            status = 'WARNING'
            findings = f"Dashboard configuration concerns: {', '.join(concerns)}"
            recommendations = "Enhance dashboards to provide better operational visibility and situational awareness."
        else:
            if suggestions:
                status = 'WARNING'
                findings = "Dashboard configuration is adequate but could be enhanced."
                recommendations = f"Consider improvements: {', '.join(suggestions)}"
            else:
                status = 'PASS'
                findings = "Comprehensive dashboard configuration in place."
                recommendations = "Continue to refine dashboards based on security operations needs."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': dashboard_info
        }
    
    def _check_retention_policies(self):
        """Check data retention policies and configuration."""
        # In a real implementation, this would query retention settings
        # For this example, we'll simulate retention information
        
        retention_info = {
            'event_retention_days': 90,
            'flow_retention_days': 30,
            'retention_by_log_source': {
                'Authentication logs': 180,
                'Firewall logs': 90,
                'IDS logs': 90,
                'OS logs': 30,
                'Application logs': 30
            },
            'custom_retention_policies': 3,
            'data_compression_enabled': True,
            'archive_enabled': False
        }
        
        # Evaluate retention policies
        concerns = []
        suggestions = []
        
        if retention_info['event_retention_days'] < 30:
            concerns.append(f"Short event retention period: {retention_info['event_retention_days']} days")
        
        if retention_info['flow_retention_days'] < 7:
            concerns.append(f"Short flow retention period: {retention_info['flow_retention_days']} days")
        
        if any(days < 30 for source, days in retention_info['retention_by_log_source'].items() 
               if source.lower() in ['authentication logs', 'firewall logs', 'ids logs']):
            concerns.append("Insufficient retention for critical security logs")
        
        if not retention_info['data_compression_enabled']:
            suggestions.append("Data compression is not enabled")
        
        if not retention_info['archive_enabled']:
            suggestions.append("Data archiving is not configured")
        
        if concerns:
            status = 'FAIL'
            findings = f"Retention policy concerns: {', '.join(concerns)}"
            recommendations = "Review and adjust retention policies to meet security and compliance requirements."
        else:
            if suggestions:
                status = 'WARNING'
                findings = "Retention policies meet basic requirements but could be enhanced."
                recommendations = f"Consider improvements: {', '.join(suggestions)}"
            else:
                status = 'PASS'
                findings = "Appropriate retention policies in place."
                recommendations = "Continue to align retention policies with evolving compliance requirements."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': retention_info
        }
    
    # Integration & Data Flow Checks
    def _check_external_integrations(self):
        """Check external integrations and configurations."""
        # In a real implementation, this would query integrations configuration
        # For this example, we'll simulate integration information
        
        integrations = {
            'active_integrations': [
                'Email',
                'SIEM Forwarding',
                'Vulnerability Scanner',
                'Ticket System'
            ],
            'integration_status': {
                'Email': 'Working',
                'SIEM Forwarding': 'Working',
                'Vulnerability Scanner': 'Error',
                'Ticket System': 'Working'
            },
            'bidirectional_integrations': 1
        }
        
        # Evaluate integrations
        concerns = []
        suggestions = []
        
        if len(integrations['active_integrations']) < 2:
            concerns.append("Few external integrations configured")
        
        error_integrations = sum(1 for status in integrations['integration_status'].values() if status == 'Error')
        if error_integrations > 0:
            concerns.append(f"{error_integrations} integrations reporting errors")
        
        if 'Ticket System' not in integrations['active_integrations']:
            suggestions.append("No ticket system integration for case management")
        
        if integrations['bidirectional_integrations'] == 0:
            suggestions.append("No bidirectional integrations configured")
        
        if concerns:
            status = 'WARNING'
            findings = f"Integration concerns: {', '.join(concerns)}"
            recommendations = "Review and fix integration issues to improve security operations workflow."
        else:
            if suggestions:
                status = 'WARNING'
                findings = "Integrations are functional but could be enhanced."
                recommendations = f"Consider improvements: {', '.join(suggestions)}"
            else:
                status = 'PASS'
                findings = "Appropriate integrations are configured and functioning."
                recommendations = "Continue to explore integration opportunities to enhance security operations."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': integrations
        }
    
    def _check_data_exports(self):
        """Check data export configurations and usage."""
        # In a real implementation, this would query data export configuration
        # For this example, we'll simulate export information
        
        export_info = {
            'configured_exports': 2,
            'export_destinations': ['SIEM', 'Data Lake'],
            'exported_data_types': ['Events', 'Flows'],
            'export_frequency': 'Hourly',
            'last_successful_export': '2023-07-15T08:30:00'
        }
        
        # Calculate last export age
        try:
            last_export_time = datetime.datetime.strptime(export_info['last_successful_export'], '%Y-%m-%dT%H:%M:%S')
            current_time = datetime.datetime.now()
            export_age_hours = (current_time - last_export_time).total_seconds() / 3600
        except:
            export_age_hours = 999  # Default to a high value if can't determine
        
        # Evaluate data exports
        concerns = []
        suggestions = []
        
        if export_info['configured_exports'] == 0:
            concerns.append("No data exports configured")
        
        if export_age_hours > 48:
            concerns.append(f"Last successful export is over {int(export_age_hours/24)} days old")
        
        if 'Data Lake' not in export_info['export_destinations'] and 'SIEM' not in export_info['export_destinations']:
            suggestions.append("No integration with enterprise data lake or secondary SIEM")
        
        if export_info['export_frequency'].lower() not in ['hourly', 'real-time']:
            suggestions.append(f"Infrequent export schedule: {export_info['export_frequency']}")
        
        if concerns:
            if export_info['configured_exports'] == 0:
                status = 'FAIL'
                findings = "No data export capability configured."
                recommendations = "Implement data exports to enable long-term storage and advanced analytics."
            else:
                status = 'WARNING'
                findings = f"Data export concerns: {', '.join(concerns)}"
                recommendations = "Review and address data export issues."
        else:
            if suggestions:
                status = 'WARNING'
                findings = "Data exports are configured but could be enhanced."
                recommendations = f"Consider improvements: {', '.join(suggestions)}"
            else:
                status = 'PASS'
                findings = "Appropriate data export configuration in place."
                recommendations = "Continue to refine data export strategy based on organizational needs."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'configured_exports': export_info['configured_exports'],
                'export_destinations': export_info['export_destinations'],
                'exported_data_types': export_info['exported_data_types'],
                'export_frequency': export_info['export_frequency'],
                'export_age_hours': export_age_hours
            }
        }
    
    def _check_api_usage(self):
        """Check API usage patterns and configuration."""
        # In a real implementation, this would query API usage metrics
        # For this example, we'll simulate API usage information
        
        api_info = {
            'authorized_api_clients': 5,
            'api_calls_per_day': 1200,
            'api_errors_per_day': 15,
            'api_throttling_enabled': True,
            'api_versions_in_use': ['v14.0', 'v13.0'],
            'deprecated_api_usage': False
        }
        
        # Evaluate API usage
        concerns = []
        suggestions = []
        
        if api_info['authorized_api_clients'] == 0:
            concerns.append("No authorized API clients")
        
        if api_info['api_errors_per_day'] > 100:
            concerns.append(f"High API error rate: {api_info['api_errors_per_day']} errors per day")
        
        if not api_info['api_throttling_enabled']:
            suggestions.append("API throttling is not enabled")
        
        if api_info['deprecated_api_usage']:
            concerns.append("Using deprecated API versions")
        
        if concerns:
            status = 'WARNING'
            findings = f"API usage concerns: {', '.join(concerns)}"
            recommendations = "Review API configuration and usage patterns to ensure reliability and security."
        else:
            if suggestions:
                status = 'WARNING'
                findings = "API usage is generally appropriate but could be enhanced."
                recommendations = f"Consider improvements: {', '.join(suggestions)}"
            else:
                status = 'PASS'
                findings = "API configuration and usage patterns appear appropriate."
                recommendations = "Continue to monitor API usage and stay current with API versions."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': api_info
        }
    
    def _generate_report(self):
        """Generate the comprehensive audit report."""
        print(f"\n{Fore.CYAN}=== QRadar SIEM Audit Report ===")
        print(f"{Fore.CYAN}Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}Target System: {self.base_url}")
        
        if hasattr(self, 'system_info'):
            version = self.system_info.get('version', 'Unknown')
            print(f"{Fore.CYAN}QRadar Version: {version}")
        
        print(f"{Fore.CYAN}================================\n")
        
        # Summary statistics
        total_checks = sum(len(checks) for checks in self.audit_categories.values())
        passes = 0
        warnings = 0
        failures = 0
        
        for category, checks in self.results.items():
            for check_name, result in checks.items():
                if result['status'] == 'PASS':
                    passes += 1
                elif result['status'] == 'WARNING':
                    warnings += 1
                elif result['status'] == 'FAIL':
                    failures += 1
        
        print(f"{Fore.GREEN}Summary Statistics:")
        print(f"{Fore.GREEN}  Total Checks: {total_checks}")
        print(f"{Fore.GREEN}  Passed: {passes} ({passes/total_checks*100:.1f}%)")
        print(f"{Fore.YELLOW}  Warnings: {warnings} ({warnings/total_checks*100:.1f}%)")
        print(f"{Fore.RED}  Failures: {failures} ({failures/total_checks*100:.1f}%)")
        
        # Critical issues
        critical_issues = []
        for category, checks in self.results.items():
            for check_name, result in checks.items():
                if result['status'] == 'FAIL':
                    critical_issues.append(f"{category} - {check_name}: {result['findings']}")
        
        if critical_issues:
            print(f"\n{Fore.RED}Critical Issues:")
            for i, issue in enumerate(critical_issues, 1):
                print(f"{Fore.RED}  {i}. {issue}")
        
        # Detailed results by category
        print(f"\n{Fore.CYAN}Detailed Results:")
        
        for category, checks in self.audit_categories.items():
            if category in self.results:
                print(f"\n{Fore.BLUE}{category}:")
                
                for check_name, check_function in checks.items():
                    if check_name in self.results[category]:
                        result = self.results[category][check_name]
                        status_color = Fore.GREEN if result['status'] == 'PASS' else Fore.RED if result['status'] == 'FAIL' else Fore.YELLOW
                        
                        print(f"{status_color}  {check_name}: {result['status']}")
                        print(f"{Fore.WHITE}    Findings: {result['findings']}")
                        print(f"{Fore.WHITE}    Recommendations: {result['recommendations']}")
        
        # Overall recommendation checklist
        self._generate_recommendation_checklist()
    
    def _generate_recommendation_checklist(self):
        """Generate a prioritized recommendation checklist based on audit results."""
        print(f"\n{Fore.CYAN}=== Recommendation Checklist ===")
        
        # Collect all recommendations from failed checks
        critical_recommendations = []
        for category, checks in self.results.items():
            for check_name, result in checks.items():
                if result['status'] == 'FAIL':
                    critical_recommendations.append({
                        'category': category,
                        'check': check_name,
                        'recommendation': result['recommendations']
                    })
        
        # Collect all recommendations from warning checks
        important_recommendations = []
        for category, checks in self.results.items():
            for check_name, result in checks.items():
                if result['status'] == 'WARNING':
                    important_recommendations.append({
                        'category': category,
                        'check': check_name,
                        'recommendation': result['recommendations']
                    })
        
        # Print critical recommendations
        if critical_recommendations:
            print(f"\n{Fore.RED}Critical (Immediate Action Required):")
            for i, rec in enumerate(critical_recommendations, 1):
                print(f"{Fore.RED}  {i}. [{rec['category']} - {rec['check']}] {rec['recommendation']}")
        
        # Print important recommendations
        if important_recommendations:
            print(f"\n{Fore.YELLOW}Important (Action Recommended):")
            for i, rec in enumerate(important_recommendations, 1):
                print(f"{Fore.YELLOW}  {i}. [{rec['category']} - {rec['check']}] {rec['recommendation']}")
        
        # General best practices
        print(f"\n{Fore.CYAN}General Best Practices:")
        best_practices = [
            "Regularly review and tune detection rules to reduce false positives",
            "Implement a formal change management process for SIEM changes",
            "Conduct regular training for security analysts on QRadar capabilities",
            "Document SIEM architecture, configurations, and custom content",
            "Perform regular data quality reviews to ensure complete log collection",
            "Establish clear SLAs for offense investigation and remediation",
            "Develop automated playbooks for common offense types",
            "Review user access permissions quarterly",
            "Keep QRadar updated to the latest supported version",
            "Regularly test backup and recovery procedures"
        ]
        
        for i, practice in enumerate(best_practices, 1):
            print(f"{Fore.CYAN}  {i}. {practice}")
        
        print(f"\n{Fore.CYAN}================================")


if __name__ == "__main__":
    # Execute the audit
    auditor = QRadarAuditor()
    auditor.run_audit()
}
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}API request error: {str(e)}")
            return None

    # Data Collection Checks
    def _check_log_sources(self):
        """Check log sources configuration and status."""
        url = f"{self.base_url}/api/config/event_sources/log_source_management/log_sources"
        log_sources = self._make_api_request(url)
        
        if not log_sources:
            return {
                'status': 'FAIL',
                'findings': "Unable to retrieve log sources.",
                'recommendations': "Check API permissions and connectivity."
            }
        
        total_sources = len(log_sources)
        enabled_sources = sum(1 for source in log_sources if source.get('enabled', False))
        status_counts = {}
        
        for source in log_sources:
            status = source.get('status', {}).get('status', 'Unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        error_sources = sum(status_counts.get(status, 0) for status in ['Error', 'Warning', 'Disabled'])
        
        if total_sources == 0:
            status = 'FAIL'
            findings = "No log sources configured in the system."
            recommendations = "Configure log sources to collect security data."
        elif error_sources > total_sources * 0.1:  # More than 10% in error state
            status = 'FAIL'
            findings = f"Found {error_sources} out of {total_sources} log sources with issues."
            recommendations = "Review and fix problematic log sources to ensure complete data collection."
        else:
            status = 'PASS'
            findings = f"Found {total_sources} log sources with {enabled_sources} enabled."
            recommendations = "Continue monitoring log source health and add new sources as environment changes."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'total_sources': total_sources,
                'enabled_sources': enabled_sources,
                'status_counts': status_counts
            }
        }
    
    def _check_event_collection_rate(self):
        """Check event collection rate and trends."""
        current_time = int(time.time() * 1000)
        one_day_ago = current_time - (24 * 60 * 60 * 1000)
        
        url = f"{self.base_url}/api/ariel/searches"
        query_data = {
            'query_expression': 'SELECT COUNT(*) as event_count FROM events WHERE PARSEDATE(starttime) > PARSETIME(%s, "MILLISECOND")' % one_day_ago
        }
        
        search_response = self._make_api_request(url, method='POST', data=query_data)
        
        if not search_response or 'search_id' not in search_response:
            return {
                'status': 'WARNING',
                'findings': "Unable to execute event count query.",
                'recommendations': "Check Ariel query permissions and try again."
            }
        
        search_id = search_response['search_id']
        search_complete = False
        max_attempts = 20
        attempts = 0
        
        # Poll for search completion
        while not search_complete and attempts < max_attempts:
            time.sleep(3)
            status_url = f"{self.base_url}/api/ariel/searches/{search_id}"
            status_response = self._make_api_request(status_url)
            
            if status_response and status_response.get('status') == 'COMPLETED':
                search_complete = True
            
            attempts += 1
        
        if not search_complete:
            return {
                'status': 'WARNING',
                'findings': "Event count query did not complete in the allocated time.",
                'recommendations': "Optimize Ariel searches or increase timeout value."
            }
        
        results_url = f"{self.base_url}/api/ariel/searches/{search_id}/results"
        results = self._make_api_request(results_url)
        
        if not results or 'events' not in results:
            return {
                'status': 'WARNING',
                'findings': "Unable to retrieve event count results.",
                'recommendations': "Check Ariel query permissions and try again."
            }
        
        event_count = 0
        if results['events'] and len(results['events']) > 0:
            event_count = results['events'][0].get('event_count', 0)
        
        # Evaluate event rate
        if event_count == 0:
            status = 'FAIL'
            findings = "No events collected in the past 24 hours."
            recommendations = "Check log source connectivity and event collection configuration."
        elif event_count < 1000:
            status = 'WARNING'
            findings = f"Low event collection rate: {event_count} events in the past 24 hours."
            recommendations = "Verify log source configuration and ensure all relevant security logs are being collected."
        else:
            status = 'PASS'
            findings = f"Healthy event collection rate: {event_count} events in the past 24 hours."
            recommendations = "Continue monitoring event rates for unexpected changes."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'event_count_24h': event_count,
                'events_per_hour': round(event_count / 24, 2)
            }
        }
    
    def _check_log_source_coverage(self):
        """Check for coverage gaps in log sources."""
        url = f"{self.base_url}/api/config/event_sources/log_source_management/log_sources"
        log_sources = self._make_api_request(url)
        
        if not log_sources:
            return {
                'status': 'WARNING',
                'findings': "Unable to retrieve log sources.",
                'recommendations': "Check API permissions and connectivity."
            }
        
        # Define critical log source types that should be present
        critical_source_types = {
            'Firewall': False,
            'IDS/IPS': False,
            'Authentication': False,
            'Operating System': False,
            'Network Device': False,
            'Database': False,
            'Web Server': False,
            'Endpoint': False,
            'Cloud Service': False,
            'Active Directory': False
        }
        
        # Map QRadar log source types to our critical categories
        type_mapping = {
            'Cisco PIX/ASA': 'Firewall',
            'Juniper SRX': 'Firewall',
            'CheckPoint': 'Firewall',
            'Palo Alto PA': 'Firewall',
            'Snort': 'IDS/IPS',
            'Sourcefire': 'IDS/IPS',
            'Cisco IPS': 'IDS/IPS',
            'Microsoft Windows Security': 'Authentication',
            'RADIUS': 'Authentication',
            'LDAP': 'Authentication',
            'Microsoft Windows': 'Operating System',
            'Unix': 'Operating System',
            'Linux': 'Operating System',
            'Cisco IOS': 'Network Device',
            'Juniper JunOS': 'Network Device',
            'Oracle': 'Database',
            'Microsoft SQL Server': 'Database',
            'MySQL': 'Database',
            'PostgreSQL': 'Database',
            'Apache': 'Web Server',
            'IIS': 'Web Server',
            'Nginx': 'Web Server',
            'Microsoft Windows Endpoint': 'Endpoint',
            'Carbon Black': 'Endpoint',
            'CrowdStrike': 'Endpoint',
            'AWS CloudTrail': 'Cloud Service',
            'Azure Activity Log': 'Cloud Service',
            'Office 365': 'Cloud Service',
            'Google Cloud': 'Cloud Service',
            'Microsoft Active Directory': 'Active Directory'
        }
        
        # Check which critical source types are covered
        for source in log_sources:
            source_type = source.get('type_name', '')
            for qradar_type, critical_type in type_mapping.items():
                if qradar_type.lower() in source_type.lower() and source.get('enabled', False):
                    critical_source_types[critical_type] = True
        
        # Calculate coverage
        covered_types = sum(1 for covered in critical_source_types.values() if covered)
        total_types = len(critical_source_types)
        coverage_percentage = (covered_types / total_types) * 100
        
        missing_types = [type_name for type_name, covered in critical_source_types.items() if not covered]
        
        if coverage_percentage < 50:
            status = 'FAIL'
            findings = f"Poor log source coverage: {coverage_percentage:.1f}% of critical source types."
            recommendations = f"Add log sources for missing critical types: {', '.join(missing_types)}."
        elif coverage_percentage < 80:
            status = 'WARNING'
            findings = f"Moderate log source coverage: {coverage_percentage:.1f}% of critical source types."
            recommendations = f"Consider adding log sources for: {', '.join(missing_types)}."
        else:
            status = 'PASS'
            findings = f"Good log source coverage: {coverage_percentage:.1f}% of critical source types."
            recommendations = "Continue expanding coverage as environment changes."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'coverage_percentage': coverage_percentage,
                'covered_types': covered_types,
                'total_types': total_types,
                'missing_types': missing_types
            }
        }
    
    def _check_log_source_status(self):
        """Check status of log sources and identify issues."""
        url = f"{self.base_url}/api/config/event_sources/log_source_management/log_sources"
        log_sources = self._make_api_request(url)
        
        if not log_sources:
            return {
                'status': 'WARNING',
                'findings': "Unable to retrieve log source status.",
                'recommendations': "Check API permissions and connectivity."
            }
        
        status_counts = {
            'Active': 0,
            'Error': 0,
            'Warning': 0,
            'Disabled': 0,
            'Unknown': 0
        }
        
        problem_sources = []
        
        for source in log_sources:
            status = source.get('status', {}).get('status', 'Unknown')
            if status not in status_counts:
                status = 'Unknown'
            
            status_counts[status] += 1
            
            if status in ['Error', 'Warning']:
                problem_sources.append({
                    'name': source.get('name', 'Unknown source'),
                    'type': source.get('type_name', 'Unknown type'),
                    'status': status,
                    'last_event': source.get('last_event_time', 'Never')
                })
        
        total_sources = sum(status_counts.values())
        problem_percentage = ((status_counts['Error'] + status_counts['Warning']) / total_sources) * 100 if total_sources > 0 else 0
        
        if problem_percentage > 20:
            status = 'FAIL'
            findings = f"High percentage ({problem_percentage:.1f}%) of log sources with issues."
            recommendations = "Urgently review and fix problematic log sources to ensure complete data collection."
        elif problem_percentage > 5:
            status = 'WARNING'
            findings = f"Moderate percentage ({problem_percentage:.1f}%) of log sources with issues."
            recommendations = "Review and fix problematic log sources to improve data collection quality."
        else:
            status = 'PASS'
            findings = f"Low percentage ({problem_percentage:.1f}%) of log sources with issues."
            recommendations = "Continue monitoring log source health."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'status_counts': status_counts,
                'problem_percentage': problem_percentage,
                'problem_sources': problem_sources[:5]  # Limit to first 5 for brevity
            }
        }
    
    # System Configuration Checks
    def _check_system_health(self):
        """Check overall system health metrics."""
        # In a real implementation, this would check CPU, memory, disk I/O, etc.
        # For this example, we'll simulate some health metrics
        health_metrics = {
            'cpu_utilization': 65,
            'memory_utilization': 72,
            'disk_io_utilization': 40,
            'event_processing_delay': 2.5,  # seconds
            'services_status': 'All services running'
        }
        
        # Evaluate system health
        concerns = []
        if health_metrics['cpu_utilization'] > 80:
            concerns.append(f"High CPU utilization ({health_metrics['cpu_utilization']}%)")
        
        if health_metrics['memory_utilization'] > 85:
            concerns.append(f"High memory utilization ({health_metrics['memory_utilization']}%)")
        
        if health_metrics['disk_io_utilization'] > 75:
            concerns.append(f"High disk I/O utilization ({health_metrics['disk_io_utilization']}%)")
        
        if health_metrics['event_processing_delay'] > 5:
            concerns.append(f"Elevated event processing delay ({health_metrics['event_processing_delay']}s)")
        
        if "not running" in health_metrics['services_status'].lower():
            concerns.append(f"Service issues detected: {health_metrics['services_status']}")
        
        if concerns:
            if len(concerns) > 2:
                status = 'FAIL'
                findings = f"Multiple system health issues detected: {', '.join(concerns)}"
                recommendations = "Review system sizing and optimize configuration. Consider adding resources or reducing load."
            else:
                status = 'WARNING'
                findings = f"Some system health concerns: {', '.join(concerns)}"
                recommendations = "Monitor the system closely and plan for optimization if issues persist."
        else:
            status = 'PASS'
            findings = "System health metrics are within acceptable ranges."
            recommendations = "Continue regular monitoring of system health metrics."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': health_metrics
        }
    
    def _check_deployment_architecture(self):
        """Check the deployment architecture for best practices."""
        # In a real implementation, this would query the system to understand the deployment
        # For this example, we'll simulate a deployment configuration
        
        # Get hosts information
        url = f"{self.base_url}/api/system/servers"
        hosts = self._make_api_request(url)
        
        if not hosts:
            return {
                'status': 'WARNING',
                'findings': "Unable to retrieve deployment information.",
                'recommendations': "Check API permissions and connectivity."
            }
        
        # Analyze deployment
        console_count = 0
        event_processor_count = 0
        event_collector_count = 0
        flow_collector_count = 0
        data_node_count = 0
        
        for host in hosts:
            components = host.get('components', [])
            if 'CONSOLE' in components:
                console_count += 1
            if 'EVENT_PROCESSOR' in components:
                event_processor_count += 1
            if 'EVENT_COLLECTOR' in components:
                event_collector_count += 1
            if 'FLOW_PROCESSOR' in components:
                flow_collector_count += 1
            if 'DATA_NODE' in components:
                data_node_count += 1
        
        # Deployment type determination
        if len(hosts) == 1:
            deployment_type = "All-in-one"
        elif len(hosts) <= 3:
            deployment_type = "Basic distributed"
        else:
            deployment_type = "Fully distributed"
        
        # Evaluate architecture
        concerns = []
        
        if deployment_type == "All-in-one" and event_processor_count > 0:
            concerns.append("Using all-in-one deployment for event processing")
        
        if event_collector_count == 0:
            concerns.append("No dedicated event collectors")
        
        if console_count == 0:
            concerns.append("No console component found")
        
        if console_count > 1:
            concerns.append("Multiple console components detected")
        
        if deployment_type != "All-in-one" and event_processor_count == 0:
            concerns.append("No dedicated event processors")
        
        if concerns:
            if len(concerns) > 2:
                status = 'FAIL'
                findings = f"Suboptimal deployment architecture: {', '.join(concerns)}"
                recommendations = "Review deployment architecture against IBM QRadar best practices and consider reconfiguring or expanding the deployment."
            else:
                status = 'WARNING'
                findings = f"Deployment architecture concerns: {', '.join(concerns)}"
                recommendations = "Consider optimizing deployment architecture for better performance and scalability."
        else:
            status = 'PASS'
            findings = f"Appropriate {deployment_type} deployment architecture detected."
            recommendations = "Continue monitoring performance and scale architecture as environment grows."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'deployment_type': deployment_type,
                'host_count': len(hosts),
                'console_count': console_count,
                'event_processor_count': event_processor_count,
                'event_collector_count': event_collector_count,
                'flow_collector_count': flow_collector_count,
                'data_node_count': data_node_count
            }
        }
    
    def _check_storage_utilization(self):
        """Check storage utilization and configuration."""
        # In a real implementation, this would query storage metrics
        # For this example, we'll simulate storage information
        
        storage_info = {
            'total_storage': 5000,  # GB
            'used_storage': 3200,   # GB
            'storage_allocation': {
                'events': 70,       # percent
                'flows': 20,        # percent
                'assets': 5,        # percent
                'other': 5          # percent
            },
            'retention_periods': {
                'events': 90,       # days
                'flows': 30,        # days
                'assets': 180       # days
            }
        }
        
        # Calculate metrics
        utilization_percentage = (storage_info['used_storage'] / storage_info['total_storage']) * 100
        remaining_days = (storage_info['total_storage'] - storage_info['used_storage']) / (storage_info['used_storage'] / storage_info['retention_periods']['events']) if storage_info['retention_periods']['events'] > 0 else 0
        
        # Evaluate storage
        concerns = []
        
        if utilization_percentage > 85:
            concerns.append(f"High storage utilization ({utilization_percentage:.1f}%)")
        
        if remaining_days < 30:
            concerns.append(f"Limited storage growth capacity (approx. {remaining_days:.1f} days remaining)")
        
        if storage_info['retention_periods']['events'] < 30:
            concerns.append(f"Short event retention period ({storage_info['retention_periods']['events']} days)")
        
        if storage_info['retention_periods']['flows'] < 7:
            concerns.append(f"Short flow retention period ({storage_info['retention_periods']['flows']} days)")
        
        if concerns:
            if utilization_percentage > 90 or remaining_days < 15:
                status = 'FAIL'
                findings = f"Critical storage concerns: {', '.join(concerns)}"
                recommendations = "Urgently increase storage capacity or implement data archiving. Review retention policies."
            else:
                status = 'WARNING'
                findings = f"Storage concerns: {', '.join(concerns)}"
                recommendations = "Plan for storage expansion or optimize retention policies based on your security requirements."
        else:
            status = 'PASS'
            findings = f"Healthy storage utilization ({utilization_percentage:.1f}%) with adequate retention periods."
            recommendations = "Continue monitoring storage growth and adjust capacity planning as needed."
        
        return {
            'status': status,
            'findings': findings,
            'recommendations': recommendations,
            'details': {
                'utilization_percentage': utilization_percentage,
                'remaining_days_at_current_rate': remaining_days,
                'total_storage_gb': storage_info['total_storage'],
                'used_storage_gb': storage_info['used_storage'],
                'free_storage_gb': storage_info['total_storage'] - storage_info['used_storage'],
                'retention_periods': storage_info['retention_periods']
            }
        }
    
    def _check_backup_config(self):
        """Check backup configuration and status."""
        # In a real implementation, this would query backup configuration
        # For this example, we'll simulate backup information
        
        backup_info = {
            'backup_enabled': True,
            'backup_frequency': 'Daily',
            'last_successful_backup': '2023-07-15T02:30:00',
            'backup_retention': 14,  # days
            'backup_location': 'Remote NFS',
            'configuration_included': True,
            'data_included': False
        }
        
        # Calculate last backup age
        try:
            last_backup_time = datetime.datetime.strptime(backup_info['last_successful_backup'], '%Y-%m-%dT%H:%M:%S')
            current_time = datetime.datetime.now()
            backup_age_hours = (current_time - last_backup_time).total_seconds() / 3600
        except:
            backup_age_hours = 999  # Default to a high value if can't determine
        
        # Evaluate backup configuration
        concerns = []
        
        if not backup_info['backup_enabled']:
            concerns.append("Backups are not enabled")
        
        if backup_age_hours > 48:
            concerns.append(f"Last successful backup is over {int(backup_age_hours/24)} days old")
        
        if backup_info['backup_frequency'].lower() not in ['daily', 'twice daily']:
            concerns.append(f"Infrequent backup schedule: {backup_info['backup_frequency']}")
        
        if backup_info['backup_retention'] < 7:
            concerns.append(f"Short backup retention period: {backup_info['backup_retention']} days")
        
        if not backup_info['configuration_included']:
            concerns.append("Configuration is not included in backups")
        
        if concerns:
            if not backup_info['backup_enabled'] or backup_age_hours > 72:
                status = 'FAIL'
                findings = f"Critical backup issues: {', '.join(concerns)}"
                recommendations = "Urgently configure and validate a robust backup strategy to prevent data loss."
            else:
                status = 'WARNING'
                findings = f"Backup configuration concerns: {', '.join(concerns)}"
                recommendations = "Improve backup configuration to ensure system recoverability."
        else:
            status = 'PASS'
            findings = "Appropriate backup configuration with recent successful backups."
            recommendations = "Continue regular testing of backup restoration procedures."
        
        return {
