# Security Policy

## Supported Versions

| Version | Supported              |
| ------- | ---------------------- |
| 2.x     | ✅ Active              |
| 1.x     | ⚠️ Critical fixes only |
| < 1.0   | ❌ End of life         |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, **please do not open a public issue**.

### Responsible Disclosure Process

1. **Email**: Send a detailed report to the maintainer via the contact listed in the repository profile
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. **Response time**: We aim to acknowledge within **48 hours** and provide a fix timeline within **7 days**

### Scope

This project handles sensitive data (API tokens, SIEM configurations). Security issues of particular concern include:

- Token exposure in logs or exports
- Insecure default configurations
- Code injection via API responses
- Unvalidated SSL/TLS bypass

### Best Practices for Users

- **Never** commit `.env` files containing API tokens
- Use a **read-only service account** with minimal API permissions
- Run audits on **trusted networks** when using `--verify-ssl False`
- Review exported reports before sharing (they may contain internal infrastructure details)
- Rotate API tokens regularly

## Acknowledgments

We appreciate security researchers who help keep this project safe. Contributors who responsibly disclose vulnerabilities will be credited in the CHANGELOG (with permission).
