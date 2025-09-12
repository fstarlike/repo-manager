# Repo Manager 1.0.0 – Professional Git Management for WordPress

<div align="center">

**Repo Manager** is a WordPress plugin that brings Git repository management to your dashboard. Version 1.0.0 is fast, secure, and designed to feel native to WordPress.

[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-blue.svg)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple.svg)](https://php.net/)
[![License](https://img.shields.io/badge/License-GPL%20v2%2B-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

</div>

## Screenshots

### Main Dashboard
<div align="center">

<img width="800" alt="Main Dashboard - Repository Management Interface" src="https://github.com/user-attachments/assets/22b1303d-f87b-42b1-9aba-b60f3f7141d8" />

<p><em>Clean, modern dashboard with repository cards and status indicators</em></p>
</div>

### Repository Details & Operations
<div align="center">

<img width="800" alt="Repository Details - Git Operations" src="https://github.com/user-attachments/assets/c87eae5a-df6e-43ac-94b9-c64aa316bdae" />

<p><em>Branch list with checkout functionality and search capabilities</em></p>
</div>

### Advanced Troubleshooting
<div align="center">
<img width="800" alt="Troubleshooting System - Diagnostic Tools" src="https://github.com/user-attachments/assets/f805ba07-398a-428e-a300-b214833faf3f" />
<p><em>Comprehensive troubleshooting system with step-by-step guidance</em></p>
</div>

### Settings & Configuration
<div align="center">

<img width="800" alt="Floating Widget - Notifications" src="https://github.com/user-attachments/assets/db8e205e-58b3-429b-bb4f-b60ad7f06f32" />


<p><em>Floating widget and branch-specific notifications system</em></p>
</div>


---

## Key Features

- **Multi-repository management**: Manage multiple Git repositories from a single interface
- **Real-time monitoring**: Live repository status updates with visual indicators
- **Troubleshooting**: Built-in diagnostic system with step-by-step guidance
- **Modern UI/UX**: Clean design guided by Material Design principles
- **Security**: Secure credential management and role-based access control
- **Multi-language support**: English, Persian (RTL), and Chinese
- **Responsive design**: Works well on desktop, tablet, and mobile devices
- **Performance**: Fast loading times and efficient resource management
- **Accessibility**: WCAG 2.1–friendly interface with keyboard navigation
- **API ready**: REST endpoints for external integrations

---

## What's Inside?

### Advanced repository management

* Manage multiple repositories from one place
* Clone repositories with URL validation and authentication
* Visual cards showing repository status
* Switch branches with conflict checks
* Commit history with diff previews
* Remote configuration for push/pull
* Tag and stash management with an intuitive interface

### UI and security

* Clean dashboard with sidebar navigation
* Responsive modals
* Notification system with customizable alerts
* Progress indicators for long-running actions
* Keyboard shortcuts for power users
* Secure credential storage
* Role-based access control
* Activity logs for audits

### UX and performance

* Light/Dark theme with auto-detect
* Mobile-friendly layout
* Accessibility built-in (screen reader and keyboard friendly)
* Optimized for speed (lazy loading, minimal overhead)
* Troubleshooting guide with practical fixes
* Automatic backup of repository settings
* REST API for external integrations

### Floating widget

* Available across all WordPress admin screens
* Quick view of repository status without leaving the page
* Instant access to common Git actions
* Real-time updates in the widget

---

## Requirements

* **WordPress:** 5.0+
* **PHP:** 7.4+
* **Git:** Installed and available on the server
* Write permissions for the plugin and repository directories

---

## Getting Started

1. Download and install the plugin
2. Activate it from your WordPress dashboard
3. Go to **Repo Manager → Settings** and set your repository paths
4. Test the connection and start managing your Git workflow

---

## Language & RTL Support

* English (default)
* Persian (with full RTL support)
* Chinese
  Layouts adjust automatically for right-to-left languages.

---

## Responsive by Design

* **Desktop:** Full dashboard with all tools
* **Tablet:** Optimized touch-friendly layout
* **Mobile:** Simplified interface for quick actions

---

## Benefits

* Easy setup with clear steps
* Visual feedback for every action
* Built-in help and troubleshooting
* Workflow optimized for developers

---

## Security

* Role-based access control, input validation, and sanitization
* Git command safety with proper escaping and validation
* Administrator-only access with configurable role permissions
* Detailed audit logs for repository operations and security events
* Nonce protection on all AJAX requests
* Path validation to prevent directory traversal
* SSH key handling with temporary storage and restricted permissions (0600)

**Note**: Git operations are executed via a controlled runner. Inputs are validated/sanitized, arguments are allowlisted, and execution is time/size limited. See [SECURITY.md](SECURITY.md) for details.

---

## Troubleshooting

* Step-by-step diagnostics for common issues
* Real-time progress updates
* One-click auto-fixes for most problems

---

## API

* REST endpoints for multi-repo operations
* JSON responses with detailed error handling
* Secure, nonce-based authentication

---

## Documentation

You’ll find:

* Setup guides
* User tutorials
* API docs
* Troubleshooting tips

---

## Reporting Issues

* Check the built-in troubleshooting first
* Review the documentation
* Open an issue on the repository with environment details

---

## License

GPLv2 or later

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

Copyright (c) 2025 Farzad Hoseinzade

---

## Thanks To

* Material Design for design principles
* GitHub Desktop & GitLab for UI inspiration
* WordPress for the integration standards
* The community for feedback and testing
