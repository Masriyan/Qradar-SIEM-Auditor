# QRadar SIEM Auditor

![QRadar SIEM Auditor](https://img.shields.io/badge/QRadar-SIEM%20Auditor-blue)
![Python Version](https://img.shields.io/badge/python-3.6%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive tool for auditing IBM QRadar SIEM implementations against security best practices, providing detailed evaluation and actionable recommendations for improvement.

## 📋 Overview

QRadar SIEM Auditor is a powerful Python utility designed to help security professionals evaluate their QRadar deployments against industry best practices. The tool conducts a thorough assessment across multiple critical dimensions of a SIEM implementation, identifying areas of concern and providing specific recommendations to enhance your security posture.

### Key Features

- **Comprehensive Assessment**: Evaluates 20+ key aspects of your QRadar deployment
- **Color-Coded Results**: Clear PASS/WARNING/FAIL indicators for each check
- **Actionable Recommendations**: Specific, prioritized improvement suggestions
- **API-Based Analysis**: Non-intrusive evaluation using QRadar's REST API
- **Detailed Reporting**: In-depth findings with supporting metrics
- **Prioritized Checklist**: Organizing recommendations by criticality

## 🔍 What Gets Audited

The QRadar SIEM Auditor evaluates six critical categories of your SIEM implementation:

### 1. Data Collection
- Log source configuration and status
- Event collection rates and trends
- Log source coverage against critical systems
- Data collection health and issues

### 2. System Configuration
- System health and performance metrics
- Deployment architecture assessment
- Storage utilization and retention
- Backup configuration and reliability

### 3. Security Configuration
- User access controls and privileges
- Password policies and enforcement
- Network security configuration
- Authentication methods and security

### 4. Detection Capabilities
- Custom rule effectiveness
- Offense configuration and management
- Detection coverage against attack techniques
- Reference set configuration and usage

### 5. Operational Efficiency
- Search performance optimization
- Report configuration and scheduling
- Dashboard effectiveness
- Data retention policies

### 6. Integration & Data Flow
- External system integrations
- Data export configuration
- API usage patterns and security

## 🚀 Installation

### Prerequisites

- Python 3.6 or higher
- Access to a QRadar instance with API permissions
- Required Python packages:
  - requests
  - pandas
  - colorama
  - python-dotenv

### Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/Masriyan/qradar-siem-auditor.git
   cd qradar-siem-auditor
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file with your QRadar credentials:
   ```
   QRADAR_URL=https://your-qradar-console.example.com
   QRADAR_TOKEN=your-api-token
   VERIFY_SSL=True
   ```

## 📊 Usage

Run the auditor with the following command:

```bash
python qradar_siem_auditor.py
```

### Example Output

```
=== QRadar SIEM Audit Tool ===
Starting audit of https://qradar.example.com
Time: 2023-07-15 14:30:45
==============================

Successfully connected to QRadar API.

Auditing Data Collection...
  Checking Log Sources...
    Status: PASS
  Checking Event Collection Rate...
    Status: WARNING
  Checking Log Source Coverage...
    Status: PASS
  Checking Log Source Status...
    Status: WARNING

[...additional output...]

=== QRadar SIEM Audit Report ===
Generated: 2023-07-15 15:12:33
Target System: https://qradar.example.com
QRadar Version: 7.5.0
================================

Summary Statistics:
  Total Checks: 22
  Passed: 15 (68.2%)
  Warnings: 5 (22.7%)
  Failures: 2 (9.1%)

Critical Issues:
  1. System Configuration - Storage Utilization: High storage utilization (92.5%)
  2. Detection Capabilities - Offense Configuration: High number of active offenses: 156

[...detailed results by category...]

=== Recommendation Checklist ===

Critical (Immediate Action Required):
  1. [System Configuration - Storage Utilization] Urgently increase storage capacity or implement data archiving. Review retention policies.
  2. [Detection Capabilities - Offense Configuration] Implement an offense handling process with clear ownership and SLAs. Consider automation for common offense types.

Important (Action Recommended):
  1. [Data Collection - Event Collection Rate] Verify log source configuration and ensure all relevant security logs are being collected.
  [...]

General Best Practices:
  1. Regularly review and tune detection rules to reduce false positives
  [...]
```

## 🛠️ Customization

### Modifying Check Thresholds

You can customize the criteria for PASS/WARNING/FAIL results by modifying the threshold values in each check function. For example, to adjust the storage utilization thresholds:

```python
# Original
if utilization_percentage > 85:
    concerns.append(f"High storage utilization ({utilization_percentage:.1f}%)")

# Modified for more strict threshold
if utilization_percentage > 75:
    concerns.append(f"High storage utilization ({utilization_percentage:.1f}%)")
```

### Adding New Checks

To add a new check to an existing category:

1. Create a new check function in the `QRadarAuditor` class
2. Add the function to the appropriate category in the `audit_categories` dictionary in `__init__`

Example:

```python
def _check_new_feature(self):
    # Implementation of the check
    return {
        'status': status,
        'findings': findings,
        'recommendations': recommendations,
        'details': details
    }

# Then add to audit_categories
self.audit_categories["Existing Category"]["New Check"] = self._check_new_feature
```

## 📄 API Requirements

The QRadar SIEM Auditor requires an authorized security token with access to the following QRadar API endpoints:

- `/api/system/about`
- `/api/system/servers`
- `/api/config/event_sources/log_source_management/log_sources`
- `/api/ariel/searches`
- `/api/siem/offenses`
- `/api/analytics/rules`
- `/api/config/access/users`
- `/api/reference_data/sets`

To create a security token with these permissions:

1. Log in to your QRadar console
2. Navigate to Admin > User Management > Authorized Services
3. Create a new authorized service with an appropriate role
4. Generate and copy the security token
5. Add the token to your `.env` file

## 🔒 Security Considerations

- Store your `.env` file securely and never commit it to version control
- Use a service account with read-only permissions where possible
- Consider running the audit during off-peak hours to minimize performance impact
- Review the API token permissions to ensure principle of least privilege

## 🤝 Contributing

Contributions to improve QRadar SIEM Auditor are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b new-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin new-feature`
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For questions, issues, or feature requests, please open an issue on the GitHub repository.

---

*Disclaimer: This tool is not affiliated with or endorsed by IBM. QRadar is a registered trademark of IBM. This tool is provided as-is with no warranty. Always test in a non-production environment first.*

