<?php

namespace WPGitManager\Service;

use WPGitManager\Admin\GitManager;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Enhanced secure Git command runner with improved security measures
 */
class SecureGitRunner
{
    /**
     * Allowed Git commands with their required arguments
     */
    private static $allowedCommands = [
        'status'       => ['--porcelain', '--short', '--branch', '--show-stash'],
        'log'          => ['--oneline', '--graph', '--decorate', '--all', '--max-count', '--since', '--until'],
        'branch'       => ['-a', '-r', '-v', '--merged', '--no-merged', '--list'],
        'checkout'     => ['-b', '-B', '--force', '--quiet'],
        'pull'         => ['--rebase', '--no-rebase', '--ff-only', '--no-ff'],
        'push'         => ['--force', '--force-with-lease', '--set-upstream', '--tags'],
        'fetch'        => ['--all', '--prune', '--tags', '--dry-run'],
        'clone'        => ['--depth', '--branch', '--single-branch', '--recursive'],
        'config'       => ['--get', '--set', '--unset', '--list', '--global', '--local'],
        'remote'       => ['-v', 'add', 'remove', 'set-url', 'get-url'],
        'add'          => ['--all', '--force', '--dry-run', '--verbose'],
        'commit'       => ['-m', '--amend', '--no-verify', '--allow-empty'],
        'diff'         => ['--cached', '--name-only', '--stat', '--word-diff'],
        'show'         => ['--name-only', '--stat', '--format'],
        'ls-remote'    => ['--heads', '--tags', '--refs'],
        'rev-parse'    => ['--abbrev-ref', '--short', '--verify'],
        'symbolic-ref' => ['--short', '--delete'],
        'describe'     => ['--tags', '--always', '--dirty'],
        'tag'          => ['-l', '-a', '-m', '--delete', '--list'],
        'merge'        => ['--no-ff', '--ff-only', '--squash', '--abort'],
        'rebase'       => ['--continue', '--abort', '--skip', '--interactive'],
        'stash'        => ['list', 'show', 'drop', 'clear', 'pop', 'apply'],
        'reset'        => ['--hard', '--soft', '--mixed', '--quiet'],
        'clean'        => ['-f', '-d', '-x', '--dry-run'],
    ];

    /**
     * Maximum command execution time (seconds)
     */
    private const MAX_EXECUTION_TIME = 30;

    /**
     * Maximum output size (bytes)
     */
    private const MAX_OUTPUT_SIZE = 1024 * 1024; // 1MB

    /**
     * Rate limiting storage
     */
    private const RATE_LIMIT_OPTION       = 'git_manager_rate_limits';

    private const RATE_LIMIT_WINDOW       = 60;

     // 1 minute
    private const RATE_LIMIT_MAX_REQUESTS = 10; // Max 10 requests per minute per user

    /**
     * Validate and sanitize Git command arguments
     */
    private static function validateGitCommand(string $command, array $args = []): array
    {
        // Extract base command
        $baseCommand = explode(' ', trim($command))[0];

        if (!isset(self::$allowedCommands[$baseCommand])) {
            $baseSafe = function_exists('sanitize_text_field') ? sanitize_text_field($baseCommand) : $baseCommand;
            throw new \InvalidArgumentException(sprintf("Command '%s' is not allowed", esc_html($baseSafe)));
        }

        // Validate arguments
        $allowedArgs   = self::$allowedCommands[$baseCommand];
        $sanitizedArgs = [];

        foreach ($args as $arg) {
            $arg = trim($arg);
            if ($arg === '' || $arg === '0') {
                continue;
            }

            // Check if it's a flag/option
            if (0 === strpos($arg, '--') || 0 === strpos($arg, '-')) {
                if (in_array($arg, $allowedArgs)) {
                    $sanitizedArgs[] = $arg;
                }
            } else {
                // For non-flag arguments, apply strict validation
                $sanitizedArgs[] = self::sanitizeArgument($arg);
            }
        }

        return $sanitizedArgs;
    }

    /**
     * Sanitize individual command arguments
     */
    private static function sanitizeArgument(string $arg): string
    {
        // Remove potentially dangerous characters
        $arg = preg_replace('/[;&|`$(){}<>]/', '', $arg);

        // Limit length
        if (strlen($arg) > 255) {
            $arg = substr($arg, 0, 255);
        }

        // Additional validation for specific patterns
        if (preg_match('/^[a-zA-Z0-9._\-\/]+$/', $arg)) {
            return $arg;
        }

        $safeArg = function_exists('sanitize_text_field') ? sanitize_text_field($arg) : $arg;
        throw new \InvalidArgumentException(sprintf('Invalid argument: %s', esc_html($safeArg)));
    }

    /**
     * Check rate limiting
     */
    private static function checkRateLimit(int $userId): bool
    {
        $limits      = get_option(self::RATE_LIMIT_OPTION, []);
        $currentTime = time();
        $windowStart = $currentTime - self::RATE_LIMIT_WINDOW;

        // Clean old entries
        if (isset($limits[$userId])) {
            $limits[$userId] = array_filter($limits[$userId], fn($timestamp) => $timestamp > $windowStart);
        } else {
            $limits[$userId] = [];
        }

        // Check if user has exceeded rate limit
        if (count($limits[$userId]) >= self::RATE_LIMIT_MAX_REQUESTS) {
            return false;
        }

        // Add current request
        $limits[$userId][] = $currentTime;
        update_option(self::RATE_LIMIT_OPTION, $limits, false);

        return true;
    }

    /**
     * Log Git command execution for audit
     */
    private static function logCommand(string $command, string $repoPath, bool $success, ?string $error = null): void
    {
        $logEntry = [
            'timestamp' => current_time('mysql'),
            'user_id'   => get_current_user_id(),
            'command'   => $command,
            'repo_path' => $repoPath,
            'success'   => $success,
            'error'     => $error,
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- $_SERVER is sanitized below
            'ip_address' => sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? 'unknown')),
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- $_SERVER is sanitized below
            'user_agent' => sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? 'unknown')),
        ];

        // Store in WordPress options (consider using custom table for production)
        $logs   = get_option('git_manager_audit_logs', []);
        $logs[] = $logEntry;

        // Keep only last 1000 entries
        if (count($logs) > 1000) {
            $logs = array_slice($logs, -1000);
        }

        update_option('git_manager_audit_logs', $logs, false);
    }

    /**
     * Validate repository path
     */
    private static function validateRepoPath(string $repoPath): string
    {
        $repoPath = rtrim($repoPath, '\\/');
        $realPath = realpath($repoPath);

        if (!$realPath) {
            $safeRepo = function_exists('sanitize_text_field') ? sanitize_text_field($repoPath) : $repoPath;
            throw new \InvalidArgumentException(sprintf('Repository path does not exist: %s', esc_html($safeRepo)));
        }

        // Ensure path is within WordPress installation
        $wpContentDir = WP_CONTENT_DIR;
        if (0 !== strpos($realPath, (string) realpath($wpContentDir))) {
            throw new \InvalidArgumentException('Repository path must be within WordPress content directory');
        }

        // Check if it's a valid Git repository
        if (!is_dir($realPath . '/.git')) {
            $safeRepo = function_exists('sanitize_text_field') ? sanitize_text_field($repoPath) : $repoPath;
            throw new \InvalidArgumentException(sprintf('Not a valid Git repository: %s', esc_html($safeRepo)));
        }

        return $realPath;
    }

    /**
     * Execute Git command with enhanced security
     */
    public static function run(string $repoPath, string $command, array $args = []): array
    {
        try {
            // Check if commands are enabled
            if (!GitManager::are_commands_enabled()) {
                return ['success' => false, 'output' => 'Command execution is disabled', 'cmd' => $command];
            }

            // Check rate limiting
            if (!self::checkRateLimit(get_current_user_id())) {
                return ['success' => false, 'output' => 'Rate limit exceeded. Please wait before making another request.', 'cmd' => $command];
            }

            // Validate inputs
            $repoPath      = self::validateRepoPath($repoPath);
            $sanitizedArgs = self::validateGitCommand($command, $args);

            // Build command
            $fullCommand = 'git -C ' . escapeshellarg($repoPath) . ' ' . $command;
            if ($sanitizedArgs !== []) {
                $fullCommand .= ' ' . implode(' ', array_map('escapeshellarg', $sanitizedArgs));
            }

            // Execute command
            $result = self::executeCommand($fullCommand);

            // Log successful execution
            self::logCommand($command, $repoPath, true);

            return [
                'success'        => true,
                'output'         => $result['output'],
                'cmd'            => $command,
                'execution_time' => $result['execution_time'],
            ];

        } catch (\InvalidArgumentException $e) {
            self::logCommand($command, $repoPath, false, $e->getMessage());
            return ['success' => false, 'output' => $e->getMessage(), 'cmd' => $command];
        } catch (\Exception $e) {
            self::logCommand($command, $repoPath, false, $e->getMessage());
            return ['success' => false, 'output' => 'Command execution failed: ' . $e->getMessage(), 'cmd' => $command];
        }
    }

    /**
     * Execute command with timeout and output limits
     */
    private static function executeCommand(string $cmd): array
    {
        $startTime = microtime(true);

        // Use proc_open for better control
        $descriptorspec = [
            0 => ['pipe', 'r'],  // stdin
            1 => ['pipe', 'w'],  // stdout
            2 => ['pipe', 'w'],   // stderr
        ];

        // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found -- Using proc_open for controlled subprocess with timeout and pipe handling
        $process = proc_open($cmd, $descriptorspec, $pipes);

        if (!is_resource($process)) {
            throw new \RuntimeException('Failed to start process');
        }

        // Close stdin
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- closing process pipe
        fclose($pipes[0]);

        // Set non-blocking mode
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $output    = '';
        $error     = '';
        $startTime = time();

        // Read output with timeout
        while (true) {
            $read   = [$pipes[1], $pipes[2]];
            $write  = null;
            $except = null;

            $ready = stream_select($read, $write, $except, 1);

            if (false === $ready) {
                break;
            }

            if ($ready > 0) {
                foreach ($read as $pipe) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- reading process pipe
                    $data = fread($pipe, 8192);
                    if (false !== $data) {
                        if ($pipe === $pipes[1]) {
                            $output .= $data;
                        } else {
                            $error .= $data;
                        }

                        // Check output size limit
                        if (strlen($output) > self::MAX_OUTPUT_SIZE) {
                            proc_terminate($process);
                            throw new \RuntimeException('Output size limit exceeded');
                        }
                    }
                }
            }

            // Check timeout
            if ((time() - $startTime) > self::MAX_EXECUTION_TIME) {
                proc_terminate($process);
                throw new \RuntimeException('Command execution timeout');
            }

            // Check if process is still running
            $status = proc_get_status($process);
            if (!$status['running']) {
                break;
            }
        }

        // Close pipes
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- closing process pipe
        fclose($pipes[1]);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- closing process pipe
        fclose($pipes[2]);

        // Get exit code
        $exitCode = proc_close($process);

        $executionTime = microtime(true) - $startTime;

        // Return output or error
        $result = $output ?: $error;

        // Mask sensitive information
        $result = self::maskSensitiveData($result);

        return [
            'output'         => $result,
            'execution_time' => round($executionTime, 3),
            'exit_code'      => $exitCode,
        ];
    }

    /**
     * Mask sensitive data in output
     */
    private static function maskSensitiveData(string $output): string
    {
        // Mask GitHub tokens
        $output = preg_replace('/(ghp_\w{36})/', '[masked]', $output);
        $output = preg_replace('/(gho_\w{36})/', '[masked]', $output);
        $output = preg_replace('/(ghu_\w{36})/', '[masked]', $output);
        $output = preg_replace('/(ghr_\w{36})/', '[masked]', $output);

        // Mask SSH keys and hashes
        $output = preg_replace('/([A-Za-z0-9]{40})/', '[masked]', $output);
        $output = preg_replace('/([A-Za-z0-9]{64})/', '[masked]', $output);

        // Mask URLs with credentials
        $output = preg_replace('#(https?://)([^:@\s]{2,}):([^@\s]{2,})@#', '$1$2:[masked]@', $output);

        return $output;
    }

    /**
     * Execute a git command in a specific directory (without requiring a .git folder).
     */
    public static function runInDirectory(string $directoryPath, string $gitArgs, array $opts = []): array
    {
        try {
            if (!GitManager::are_commands_enabled()) {
                return ['success' => false, 'output' => 'Command execution is disabled', 'cmd' => $gitArgs];
            }

            // Basic path validation (within wp-content and must exist)
            $realDir = realpath($directoryPath);
            if (!$realDir || !is_dir($realDir)) {
                return ['success' => false, 'output' => 'Directory does not exist: ' . $directoryPath, 'cmd' => $gitArgs];
            }

            $wpContentDir = realpath(WP_CONTENT_DIR);
            if (0 !== strpos($realDir, (string) $wpContentDir)) {
                return ['success' => false, 'output' => 'Directory must be within WordPress content directory', 'cmd' => $gitArgs];
            }

            $fullCommand = self::buildEnvPrefix($opts) . 'git -C ' . escapeshellarg($realDir) . ' ' . $gitArgs . ' 2>&1';
            $result      = self::executeCommand($fullCommand);

            return [
                'success'        => (0 === $result['exit_code']),
                'output'         => $result['output'],
                'cmd'            => $gitArgs,
                'execution_time' => $result['execution_time'],
                'exit_code'      => $result['exit_code'],
            ];
        } catch (\Exception $exception) {
            return ['success' => false, 'output' => 'Command execution failed: ' . $exception->getMessage(), 'cmd' => $gitArgs];
        }
    }

    /**
     * Execute a system-level git command (no -C, no repo required), e.g. `git --version` or global config.
     */
    public static function runSystem(string $gitArgs, array $opts = []): array
    {
        try {
            if (!GitManager::are_commands_enabled()) {
                return ['success' => false, 'output' => 'Command execution is disabled', 'cmd' => $gitArgs];
            }

            $fullCommand = self::buildEnvPrefix($opts) . 'git ' . $gitArgs . ' 2>&1';
            $result      = self::executeCommand($fullCommand);

            return [
                'success'        => (0 === $result['exit_code']),
                'output'         => $result['output'],
                'cmd'            => $gitArgs,
                'execution_time' => $result['execution_time'],
                'exit_code'      => $result['exit_code'],
            ];
        } catch (\Exception $exception) {
            return ['success' => false, 'output' => 'Command execution failed: ' . $exception->getMessage(), 'cmd' => $gitArgs];
        }
    }

    /**
     * Get git version string.
     */
    public static function gitVersion(): array
    {
        return self::runSystem('--version');
    }

    /**
     * Clone a repository into target directory. Supports HTTPS or SSH with optional key.
     */
    public static function cloneRepository(string $remoteUrl, string $targetDirectory, array $opts = []): array
    {
        try {
            if (!GitManager::are_commands_enabled()) {
                return ['success' => false, 'output' => 'Command execution is disabled', 'cmd' => 'clone'];
            }

            // Ensure parent directory exists
            $parentDir = dirname($targetDirectory);
            if (!is_dir($parentDir) && !wp_mkdir_p($parentDir)) {
                return ['success' => false, 'output' => 'Failed to create parent directory: ' . $parentDir, 'cmd' => 'clone'];
            }

            $envPrefix = self::buildEnvPrefix($opts);
            $cmd       = $envPrefix . 'git clone ' . escapeshellarg($remoteUrl) . ' ' . escapeshellarg($targetDirectory) . ' 2>&1';
            $result    = self::executeCommand($cmd);

            $success = (0 === $result['exit_code']) && is_dir(rtrim($targetDirectory, '\\/') . '/.git');

            return [
                'success'        => $success,
                'output'         => $result['output'],
                'cmd'            => 'clone',
                'execution_time' => $result['execution_time'],
                'exit_code'      => $result['exit_code'],
            ];
        } catch (\Exception $exception) {
            return ['success' => false, 'output' => 'Clone failed: ' . $exception->getMessage(), 'cmd' => 'clone'];
        }
    }

    /**
     * Set local safe.directory for a repository path.
     */
    public static function setLocalSafeDirectory(string $repoPath): array
    {
        $real = realpath($repoPath) ?: $repoPath;
        return self::runInDirectory($real, 'config --local --add safe.directory ' . escapeshellarg($real));
    }

    /**
     * Get remote.origin.url for a repository path.
     */
    public static function getRemoteOriginUrl(string $repoPath): array
    {
        return self::runInDirectory($repoPath, 'config --get remote.origin.url');
    }

    /**
     * Build environment prefix including HOME and optional GIT_SSH wrapper for SSH key usage.
     */
    private static function buildEnvPrefix(array $opts): string
    {
        $home      = getenv('HOME') ?: (getenv('USERPROFILE') ?: sys_get_temp_dir());
        $homeClean = str_replace('"', '', $home);
        $prefix    = '';

        // SSH key wrapper support
        if (!empty($opts['ssh_key'])) {
            $keyContent = (string) $opts['ssh_key'];
            $uploads    = wp_upload_dir(null, false);
            $tmpDir     = rtrim($uploads['basedir'], '\\/') . '/repo-manager-keys';
            if (!is_dir($tmpDir)) {
                @wp_mkdir_p($tmpDir);
            }

            $keyPath = $tmpDir . '/key_' . md5($keyContent) . '.pem';
            if (!file_exists($keyPath)) {
                file_put_contents($keyPath, $keyContent);
            }

            $isWin   = ('WIN' === strtoupper(substr(PHP_OS, 0, 3)));
            $wrapper = $tmpDir . '/ssh_wrapper_' . md5($keyPath) . ($isWin ? '.bat' : '.sh');

            if ($isWin) {
                if (!file_exists($wrapper)) {
                    file_put_contents($wrapper, "@echo off\nssh -i \"{$keyPath}\" -o StrictHostKeyChecking=no %*\n");
                }

                $prefix .= 'set "GIT_SSH=' . $wrapper . '" && ';
            } else {
                if (!file_exists($wrapper)) {
                    file_put_contents($wrapper, "#!/bin/sh\nexec ssh -i '" . $keyPath . "' -o StrictHostKeyChecking=no \"$@\"\n");
                }

                $prefix .= 'GIT_SSH=' . escapeshellarg($wrapper) . ' ';
            }
        }

        if ('WIN' === strtoupper(substr(PHP_OS, 0, 3))) {
            $prefix = 'set "HOME=' . $homeClean . '" && ' . $prefix;
        } else {
            $prefix = 'HOME=' . escapeshellarg($home) . ' ' . $prefix;
        }

        return $prefix;
    }

    /**
     * Get audit logs
     */
    public static function getAuditLogs(int $limit = 100): array
    {
        $logs = get_option('git_manager_audit_logs', []);
        return array_slice($logs, -$limit);
    }

    /**
     * Clear audit logs
     */
    public static function clearAuditLogs(): void
    {
        delete_option('git_manager_audit_logs');
    }

    /**
     * Get rate limit status
     */
    public static function getRateLimitStatus(int $userId): array
    {
        $limits      = get_option(self::RATE_LIMIT_OPTION, []);
        $currentTime = time();
        $windowStart = $currentTime - self::RATE_LIMIT_WINDOW;

        $userRequests   = $limits[$userId] ?? [];
        $recentRequests = array_filter($userRequests, fn($timestamp) => $timestamp > $windowStart);

        return [
            'current_requests'   => count($recentRequests),
            'max_requests'       => self::RATE_LIMIT_MAX_REQUESTS,
            'window_seconds'     => self::RATE_LIMIT_WINDOW,
            'remaining_requests' => max(0, self::RATE_LIMIT_MAX_REQUESTS - count($recentRequests)),
        ];
    }
}
