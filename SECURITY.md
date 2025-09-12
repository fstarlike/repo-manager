# Security Documentation

## Overview

WP Repo Manager is a WordPress Plugin that provides Git repository management functionality. This document outlines the security measures implemented and explains why certain security decisions were made.

## Security Features

### 1. Role-Based Access Control
- Plugin access is restricted to users with specific roles (default: administrator)
- All AJAX endpoints verify user capabilities before execution
- Nonce verification on all user actions

### 2. Input Sanitization
- All user inputs are sanitized using WordPress sanitization functions
- File paths are validated to prevent directory traversal attacks
- Repository URLs are validated and sanitized

### 3. Nonce Protection
- All AJAX requests require valid nonces
- Nonces are unique per action and user session
- Nonce verification prevents CSRF attacks

## Git Command Execution Model

### Controlled Runner (No Direct shell_exec)

WP Repo Manager executes Git commands via a controlled runner (`SecureGitRunner`) instead of direct `shell_exec()` calls. This provides:

1. **Command Allowlisting**: Only specific Git commands/flags are allowed
2. **Path Validation**: Repository paths are validated and restricted within WordPress content directory
3. **Input Sanitization**: All arguments are sanitized and length-limited
4. **Rate Limiting**: Per-user request throttling to mitigate abuse
5. **Timeouts & Output Caps**: Hard limits on execution time and output size
6. **Audit Logging**: Command metadata stored for security audits
7. **SSH Key Handling**: Optional temporary wrappers with least-privilege permissions (0600)

### Example (Internal)

```php
$result = SecureGitRunner::runInDirectory($repoPath, 'status --porcelain');
```

### Security Considerations

1. **Server Environment**: This plugin should only be used on trusted servers
2. **User Access**: Limit access to trusted administrators only
3. **File Permissions**: Ensure proper file permissions on repository directories
4. **SSH Keys**: SSH keys are stored temporarily with restricted permissions (0600)

## Best Practices for Users

1. **Server Security**: Use on trusted, secure servers only
2. **User Management**: Limit Plugin access to necessary administrators
3. **Regular Updates**: Keep the Plugin updated to latest version
4. **Audit Logs**: Monitor Plugin activity logs regularly
5. **Backup**: Regularly backup repository configurations

## Compliance with WordPress Guidelines

This Plugin complies with WordPress Plugin Directory guidelines:

- ✅ **GPL License**: Uses GPLv2 or later license
- ✅ **No Trialware**: All functionality is available without payment
- ✅ **No User Tracking**: No external analytics or tracking
- ✅ **Code Quality**: Well-structured, readable code
- ✅ **Security**: Proper input validation and sanitization
- ✅ **Documentation**: Comprehensive security documentation

## Reporting Security Issues

If you discover a security vulnerability, please:

1. **Do not** disclose it publicly
2. **Email** security details to: fstarlike@gmail.com
3. **Include** detailed reproduction steps
4. **Allow** reasonable time for response and fix

## Version History

- **2.0.0**: Enhanced security with improved input validation and role-based access control
- **1.4.2**: Added comprehensive security measures and audit logging
- **1.1.0**: Initial security implementation with nonce protection

---

**Note**: This Plugin is designed for development and staging environments where administrators have full control over the server. Use with appropriate caution in production environments.
