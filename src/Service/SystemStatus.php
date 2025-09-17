<?php

namespace WPGitManager\Service;

use WPGitManager\Admin\GitManager;

if (! defined('ABSPATH')) {
    exit;
}

class SystemStatus
{
    /**
     * Gather all status checks grouped by category.
     */
    public static function gather(): array
    {
        $environment = self::environmentChecks();
        $wordpress   = self::wordpressChecks();
        $git         = self::gitChecks();

        $summary = ['pass' => 0, 'warn' => 0, 'fail' => 0];
        foreach ([$environment, $wordpress, $git] as $group) {
            foreach ($group as $item) {
                if (isset($summary[$item['status']])) {
                    $summary[$item['status']]++;
                }
            }
        }

        return [
            'summary'     => $summary,
            'environment' => $environment,
            'wordpress'   => $wordpress,
            'git'         => $git,
        ];
    }

    public static function gitAvailable(): bool
    {
        if (!GitManager::are_commands_enabled()) {
            return false;
        }

        $version = SecureGitRunner::gitVersion();
        return (bool) ($version['success'] ?? false);
    }

    private static function environmentChecks(): array
    {
        $isWindows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
        $memory    = ini_get('memory_limit');
        $exec      = self::executionEnabled();

        return [
            [
                'label'   => 'Operating System',
                'value'   => php_uname('s') . ' ' . php_uname('r'),
                'status'  => 'pass',
                'message' => $isWindows ? 'Windows detected' : 'Unix-like OS detected',
            ],
            [
                'label'   => 'PHP Version',
                'value'   => PHP_VERSION,
                'status'  => version_compare(PHP_VERSION, '7.4', '>=') ? 'pass' : 'fail',
                'message' => version_compare(PHP_VERSION, '7.4', '>=') ? '' : 'Requires PHP 7.4 or higher',
            ],
            [
                'label'   => 'Memory Limit',
                'value'   => (string) $memory,
                'status'  => self::memorySufficient($memory) ? 'pass' : 'warn',
                'message' => self::memorySufficient($memory) ? '' : 'Consider increasing memory_limit to 256M for smoother operations',
            ],
            [
                'label'   => 'Command Execution',
                'value'   => GitManager::are_commands_enabled() ? 'Enabled' : 'Disabled',
                'status'  => GitManager::are_commands_enabled() ? 'pass' : 'fail',
                'message' => GitManager::are_commands_enabled() ? '' : 'Enable command execution in plugin settings to use Git operations',
                'action'  => GitManager::are_commands_enabled() ? null : [
                    'label' => __('Open Settings', 'repo-manager'),
                    'url'   => admin_url('admin.php?page=repo-manager-settings'),
                ],
            ],
        ];
    }

    private static function wordpressChecks(): array
    {
        global $wp_version;

        $fsWritable = is_writable(WP_CONTENT_DIR);

        return [
            [
                'label'   => 'WordPress Version',
                'value'   => $wp_version,
                'status'  => version_compare($wp_version, '5.0', '>=') ? 'pass' : 'fail',
                'message' => version_compare($wp_version, '5.0', '>=') ? '' : 'Requires WordPress 5.0 or higher',
            ],
            [
                'label'   => 'Site URL',
                'value'   => get_site_url(),
                'status'  => 'pass',
                'message' => '',
            ],
            [
                'label'   => 'WP_CONTENT writable',
                'value'   => $fsWritable ? 'Writable' : 'Not writable',
                'status'  => $fsWritable ? 'pass' : 'warn',
                'message' => $fsWritable ? '' : 'Some operations may require write access to wp-content',
            ],
        ];
    }

    private static function gitChecks(): array
    {
        $gitEnabled  = GitManager::are_commands_enabled();
        $gitVersion  = $gitEnabled ? SecureGitRunner::gitVersion() : ['success' => false, 'output' => ''];
        $available   = $gitEnabled && (bool) ($gitVersion['success'] ?? false);
        $versionText = $available ? trim((string) ($gitVersion['output'] ?? '')) : '';

        $checks = [
            [
                'label'   => 'Git Binary',
                'value'   => $available ? $versionText : 'Not available',
                'status'  => $available ? 'pass' : 'fail',
                'message' => $available ? '' : 'Git is not available or cannot be executed by PHP',
                'action'  => $available ? null : [
                    'label'     => __('Auto-install via SSH', 'repo-manager'),
                    'url'       => '#',
                    'external'  => false,
                    'secondary' => false,
                    'data_action' => 'ssh-git-install',
                ],
            ],
        ];

        if (!$available) {
            // Add SSH installation checks
            $sshChecks = self::sshInstallationChecks();
            $checks = array_merge($checks, $sshChecks);
        }

        if ($available) {
            // Global config checks (safe to read)
            $userName = SecureGitRunner::runSystem('config --global --get user.name');
            $userMail = SecureGitRunner::runSystem('config --global --get user.email');

            $checks[] = [
                'label'   => 'Git user.name',
                'value'   => trim((string) ($userName['output'] ?? '')) ?: '-',
                'status'  => (isset($userName['success']) && $userName['success'] && '' !== trim((string) ($userName['output'] ?? ''))) ? 'pass' : 'warn',
                'message' => (isset($userName['success']) && $userName['success'] && '' !== trim((string) ($userName['output'] ?? ''))) ? '' : 'Optional but recommended to set your global user.name',
            ];

            $checks[] = [
                'label'   => 'Git user.email',
                'value'   => trim((string) ($userMail['output'] ?? '')) ?: '-',
                'status'  => (isset($userMail['success']) && $userMail['success'] && '' !== trim((string) ($userMail['output'] ?? ''))) ? 'pass' : 'warn',
                'message' => (isset($userMail['success']) && $userMail['success'] && '' !== trim((string) ($userMail['output'] ?? ''))) ? '' : 'Optional but recommended to set your global user.email',
            ];
        }

        return $checks;
    }

    /**
     * Determine if a git config command returned a usable value.
     */
    private static function hasValue(array $result): bool
    {
        if (!($result['success'] ?? false)) {
            return false;
        }
        $out = trim((string) ($result['output'] ?? ''));
        return $out !== '' && $out !== '0';
    }

    private static function sshInstallationChecks(): array
    {
        $osInfo = self::getOperatingSystemInfo();
        $sshAvailable = self::checkSSHAvailability();

        return [
            [
                'label'   => 'Operating System',
                'value'   => $osInfo['name'] . ' ' . $osInfo['version'],
                'status'  => 'pass',
                'message' => 'Detected OS for Git installation',
            ],
            [
                'label'   => 'SSH Client',
                'value'   => $sshAvailable ? 'Available' : 'Not available',
                'status'  => $sshAvailable ? 'pass' : 'fail',
                'message' => $sshAvailable ? 'SSH client is available for remote installation' : 'SSH client is required for remote Git installation',
            ],
            [
                'label'   => 'Package Manager',
                'value'   => $osInfo['package_manager'] ?? 'Unknown',
                'status'  => isset($osInfo['package_manager']) ? 'pass' : 'warn',
                'message' => isset($osInfo['package_manager']) ? 'Package manager detected for Git installation' : 'Package manager not detected',
            ],
        ];
    }

    private static function getOperatingSystemInfo(): array
    {
        $os = strtoupper(substr(PHP_OS, 0, 3));
        $uname = php_uname();

        $info = [
            'name' => php_uname('s'),
            'version' => php_uname('r'),
            'arch' => php_uname('m'),
        ];

        // Detect package manager and installation commands
        if ($os === 'WIN') {
            $info['package_manager'] = 'Windows';
            $info['install_command'] = 'winget install --id Git.Git -e --source winget';
            $info['alternative_command'] = 'choco install git';
        } elseif ($os === 'LIN' || $os === 'DAR') {
            // Check for common package managers
            $packageManagers = [
                'apt' => 'apt-get update && apt-get install -y git',
                'yum' => 'yum install -y git',
                'dnf' => 'dnf install -y git',
                'pacman' => 'pacman -S --noconfirm git',
                'brew' => 'brew install git',
                'zypper' => 'zypper install -y git',
            ];

            foreach ($packageManagers as $pm => $cmd) {
                $check = SecureGitRunner::runSystem('which ' . $pm);
                if ($check['success'] && trim($check['output'])) {
                    $info['package_manager'] = $pm;
                    $info['install_command'] = $cmd;
                    break;
                }
            }
        }

        return $info;
    }

    private static function checkSSHAvailability(): bool
    {
        $sshCheck = SecureGitRunner::findExecutable('ssh');
        return $sshCheck['success'] && trim($sshCheck['output']) !== '';
    }

    public static function installGitViaSSH(string $host, string $username, string $password = '', string $keyContent = '', string $port = ''): array
    {
        try {
            $osInfo = self::getOperatingSystemInfo();

            if (!isset($osInfo['install_command'])) {
                return [
                    'success' => false,
                    'message' => 'No suitable installation method found for this operating system',
                ];
            }

            $sshCommand = self::buildSSHCommand($host, $username, $password, $keyContent, $port);
            $installCommand = $sshCommand . ' "' . $osInfo['install_command'] . '"';

            $result = SecureGitRunner::runSshCommand($installCommand);

            if ($result['success']) {
                // Verify installation on the remote host
                $verifyCommand = $sshCommand . ' "git --version"';
                $verifyResult  = SecureGitRunner::runSshCommand($verifyCommand);
                if ($verifyResult['success']) {
                    return [
                        'success' => true,
                        'message' => 'Git installed successfully via SSH',
                        'version' => trim($verifyResult['output']),
                    ];
                }
            }

            $friendly = self::parseSshError((string) ($result['output'] ?? ''));
            return [
                'success' => false,
                'message' => $friendly,
                'raw'     => $result['output'] ?? null,
                'exit'    => $result['exit_code'] ?? null,
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'SSH installation error: ' . $e->getMessage(),
            ];
        }
    }

    private static function buildSSHCommand(string $host, string $username, string $password = '', string $keyContent = '', string $port = ''): string
    {
        $sshCmd = 'ssh';
        $tempKeyFile = null;

        if ($keyContent) {
            $uploads = wp_upload_dir(null, false);
            $keysDir = rtrim($uploads['basedir'], '\\/') . '/repo-manager-keys';
            if (!is_dir($keysDir)) {
                if (!wp_mkdir_p($keysDir)) {
                    throw new \Exception('Could not create directory for SSH keys.');
                }
                // Add security files
                $htAccess = $keysDir . '/.htaccess';
                if (!file_exists($htAccess)) {
                    @file_put_contents($htAccess, 'deny from all');
                }
                $indexFile = $keysDir . '/index.php';
                if (!file_exists($indexFile)) {
                    @file_put_contents($indexFile, '<?php // Silence is golden.');
                }
            }

            $tempKeyFile = $keysDir . '/temp_key_' . bin2hex(random_bytes(8)) . '.pem';
            if (file_put_contents($tempKeyFile, $keyContent) === false || !chmod($tempKeyFile, 0600)) {
                if (file_exists($tempKeyFile)) {
                    @unlink($tempKeyFile);
                }
                throw new \Exception('Could not create temporary SSH key file in a secure location.');
            }
            $sshCmd .= ' -i ' . escapeshellarg($tempKeyFile);
        }

        if ($port && is_numeric($port)) {
            $sshCmd .= ' -p ' . escapeshellarg($port);
        }

        $sshCmd .= ' -o StrictHostKeyChecking=no';
        // Use OS-appropriate null device for known_hosts suppression
        $isWin = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
        $sshCmd .= ' -o UserKnownHostsFile=' . ($isWin ? 'NUL' : '/dev/null');
        // Make SSH fail fast and non-interactive
        $sshCmd .= ' -o ConnectTimeout=10 -o BatchMode=yes -o LogLevel=VERBOSE';
        // Help authentication negotiation to avoid ambiguous failures
        $sshCmd .= ' -o PreferredAuthentications=publickey,password,keyboard-interactive';
        // Additional Windows-specific options
        if ($isWin) {
            $sshCmd .= ' -o ServerAliveInterval=5 -o ServerAliveCountMax=3';
        }

        if ($password) {
            // Use sshpass if available for password authentication
            $sshpassCheck = SecureGitRunner::findExecutable('sshpass');
            if ($sshpassCheck['success'] && trim($sshpassCheck['output'])) {
                $sshCmd = 'sshpass -p ' . escapeshellarg($password) . ' ' . $sshCmd;
            }
        }

        $sshCmd .= ' ' . escapeshellarg($username . '@' . $host);

        // Clean up temporary key file after command execution
        if ($tempKeyFile && file_exists($tempKeyFile)) {
            register_shutdown_function(function () use ($tempKeyFile) {
                if (file_exists($tempKeyFile)) {
                    if (!@unlink($tempKeyFile)) {
                        // Log error if unlink fails
                        error_log('Failed to delete temporary SSH key file on shutdown: ' . $tempKeyFile);
                    }
                }
            });
        }


        return $sshCmd;
    }

    /**
     * Parse SSH stderr/stdout to a friendly, actionable message.
     */
    private static function parseSshError(string $rawOutput): string
    {
        $text = strtolower(trim($rawOutput));
        if ($text === '' || $text === '0') {
            return 'SSH connection failed (no output). Check host/port/network connectivity.';
        }

        $map = [
            ['pattern' => '/name or service not known|could not resolve hostname|temporary failure in name resolution/', 'msg' => 'Host not found. Check the hostname or DNS.'],
            ['pattern' => '/no route to host|network is unreachable|operation timed out|connection timed out|timed out/', 'msg' => 'Network unreachable or timeout. Check connectivity and firewall.'],
            ['pattern' => '/connection refused/', 'msg' => 'Connection refused. Verify port and that SSH service is running.'],
            ['pattern' => '/permission denied \(publickey\)/', 'msg' => 'Permission denied (publickey). The SSH key is missing or not authorized on the server.'],
            ['pattern' => '/permission denied.*password/', 'msg' => 'Permission denied (password). Check username/password or disable password auth if using keys.'],
            ['pattern' => '/authenticat(ion|e) failed|no supported authentication methods available/', 'msg' => 'Authentication failed. Ensure the correct key/password and that the server allows it.'],
            ['pattern' => '/permission denied/', 'msg' => 'Permission denied. Check credentials and server auth settings.'],
            ['pattern' => '/no matching key exchange method found|no matching host key type found/', 'msg' => 'Key exchange/host key algorithm mismatch. Update server/client crypto algorithms.'],
            ['pattern' => '/could not resolve port|bad port number/', 'msg' => 'Invalid SSH port. Use a numeric port between 1-65535.'],
            ['pattern' => '/unknown user|invalid user/', 'msg' => 'Invalid username on the SSH server.'],
            ['pattern' => '/too many authentication failures/', 'msg' => 'Too many authentication failures. Limit identities or specify the correct key.'],
            ['pattern' => '/unprotected private key file|bad permissions|permissions are too open|incorrect permissions/', 'msg' => 'SSH key file permissions are too open. Set permissions to 600.'],
            ['pattern' => '/host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/', 'msg' => 'Host key verification failed. Clear/update known_hosts or verify host identity.'],
            ['pattern' => '/kex_exchange_identification: read: connection reset|kex_exchange_identification: banner line contains invalid characters/', 'msg' => 'SSH handshake failed. A proxy, firewall, or non-SSH service may be on that port.'],
            ['pattern' => '/ssh: command not found|not recognized as an internal or external command/', 'msg' => 'SSH client not available on this system.'],
            ['pattern' => '/unable to read private key|invalid format|load key.*invalid/', 'msg' => 'Invalid or unsupported private key format. Use PEM/OpenSSH private key.'],
        ];

        foreach ($map as $rule) {
            if (preg_match($rule['pattern'], $text)) {
                return $rule['msg'];
            }
        }

        // Default: return sanitized snippet of original error
        $snippet = substr($rawOutput, 0, 300);
        return 'SSH error: ' . trim($snippet);
    }

    public static function testSSHConnection(string $host, string $username, string $password = '', string $keyContent = '', string $port = ''): array
    {
        try {
            $sshCommand = self::buildSSHCommand($host, $username, $password, $keyContent, $port);
            $testCommand = $sshCommand . ' "echo SSH_CONNECTION_SUCCESS"';

            $result = SecureGitRunner::runSshCommand($testCommand);

            if ($result['success'] && strpos($result['output'], 'SSH_CONNECTION_SUCCESS') !== false) {
                return [
                    'success' => true,
                    'message' => 'SSH connection successful',
                    'cmd'     => $testCommand,
                    'exit'    => $result['exit_code'] ?? null,
                    'raw'     => $result['output'] ?? null,
                ];
            }

            $friendly = self::parseSshError((string) ($result['output'] ?? ''));

            // Handle specific exit codes
            $exitCode = $result['exit_code'] ?? null;
            if ($exitCode === 255) {
                $friendly = 'SSH connection failed (exit 255). Check host/port/network connectivity and SSH service status.';
            } elseif ($exitCode === 1) {
                $friendly = 'SSH authentication failed. Check credentials and key permissions.';
            }

            return [
                'success' => false,
                'message' => $friendly,
                'raw'     => $result['output'] ?? null,
                'exit'    => $exitCode,
                'cmd'     => $testCommand,
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'SSH test error: ' . $e->getMessage(),
            ];
        }
    }

    private static function memorySufficient($memory): bool
    {
        if ('-1' === trim((string) $memory)) {
            return true; // Unlimited memory
        }
        $bytes = self::toBytes($memory);
        return $bytes === 0 ? true : $bytes >= 256 * 1024 * 1024; // 256M
    }

    private static function toBytes($val): int
    {
        $val = trim((string) $val);
        if ('' === $val || '0' === $val) {
            return 0;
        }
        $last = strtolower($val[strlen($val) - 1]);
        $num  = (int) $val;
        switch ($last) {
            case 'g':
                $num *= 1024;
            // no break
            case 'm':
                $num *= 1024;
            // no break
            case 'k':
                $num *= 1024;
        }
        return $num;
    }

    private static function executionEnabled(): bool
    {
        // The plugin gates execution via option; PHP-level functions may still be disabled
        $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
        foreach (['proc_open', 'shell_exec', 'exec', 'popen'] as $fn) {
            if (in_array($fn, $disabled, true)) {
                return false;
            }
        }
        return true;
    }
}
