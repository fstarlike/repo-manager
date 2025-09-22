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
        'show-ref'     => ['--heads', '--tags', '--verify'],
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
    private const RATE_LIMIT_OPTION = 'git_manager_rate_limits';

    /**
     * Default rate limit window (seconds)
     */
    private const DEFAULT_RATE_LIMIT_WINDOW = 60;

    /**
     * Default max requests per window, applied when no per-command override exists
     */
    private const DEFAULT_RATE_LIMIT_MAX_REQUESTS = 120;

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
        $isCommitMsg   = false;

        foreach ($args as $arg) {
            $arg = trim($arg);
            if ('' === $arg) {
                continue;
            }

            if ($isCommitMsg) {
                // This argument is the commit message content, allow more characters
                $sanitizedArgs[] = $arg;
                $isCommitMsg     = false;
                continue;
            }

            // Check if it's a flag/option
            if (0 === strpos($arg, '--') || 0 === strpos($arg, '-')) {
                if (in_array($arg, $allowedArgs)) {
                    $sanitizedArgs[] = $arg;
                    // Check if this is the commit message flag
                    if ('-m' === $arg) {
                        $isCommitMsg = true;
                    }
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
        // Allow a safe set of characters for paths, branches, etc.
        // This is intentionally stricter than full shell escaping, which happens later.
        if (!preg_match('/^[a-zA-Z0-9._\-\/@]+$/', $arg)) {
            $safeArg = function_exists('sanitize_text_field') ? sanitize_text_field($arg) : $arg;
            throw new \InvalidArgumentException(sprintf('Invalid characters in argument: %s', esc_html($safeArg)));
        }

        // Prevent path traversal
        if (strpos($arg, '..') !== false) {
            throw new \InvalidArgumentException('Path traversal detected in argument');
        }

        // Limit length
        if (strlen($arg) > 1024) {
            $arg = substr($arg, 0, 1024);
        }

        return $arg;
    }

    /**
     * Determine per-command rate limit configuration.
     */
    private static function getRateLimitConfigForCommand(string $command): array
    {
        // Sanitize to base command token
        $base = explode(' ', trim($command))[0];

        // Read-only commands get very generous limits
        $map = [
            'status'     => ['max' => 200, 'window' => 60],
            'branch'     => ['max' => 200, 'window' => 60],
            'rev-parse'  => ['max' => 200, 'window' => 60],
            'show'       => ['max' => 120, 'window' => 60],
            'log'        => ['max' => 120, 'window' => 60],
            'describe'   => ['max' => 120, 'window' => 60],
            'ls-remote'  => ['max' => 120, 'window' => 60],
            // Mutating/network commands
            'fetch'      => ['max' => 60,  'window' => 60],
            'pull'       => ['max' => 60,  'window' => 60],
            'push'       => ['max' => 30,  'window' => 60],
            'clone'      => ['max' => 3,   'window' => 300],
            'merge'      => ['max' => 30,  'window' => 60],
            'checkout'   => ['max' => 120, 'window' => 60],
            'commit'     => ['max' => 60,  'window' => 60],
            'stash'      => ['max' => 60,  'window' => 60],
            'tag'        => ['max' => 60,  'window' => 60],
            'remote'     => ['max' => 60,  'window' => 60],
        ];

        return $map[$base] ?? ['max' => self::DEFAULT_RATE_LIMIT_MAX_REQUESTS, 'window' => self::DEFAULT_RATE_LIMIT_WINDOW];
    }

    /**
     * Check rate limiting (per-user, per-command)
     */
    private static function checkRateLimit(int $userId, string $command): bool
    {
        $limits      = get_option(self::RATE_LIMIT_OPTION, []);
        $currentTime = time();
        $config      = self::getRateLimitConfigForCommand($command);
        $windowStart = $currentTime - (int) $config['window'];

        // Use composite key so commands have independent budgets
        $key = $userId . ':' . explode(' ', trim($command))[0];

        // Clean old entries
        if (isset($limits[$key])) {
            $limits[$key] = array_filter($limits[$key], fn ($timestamp) => $timestamp > $windowStart);
        } else {
            $limits[$key] = [];
        }

        // Check if user has exceeded rate limit for this command
        if (count($limits[$key]) >= (int) $config['max']) {
            return false;
        }

        // Add current request
        $limits[$key][] = $currentTime;
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

        // Check if it's a valid Git repository (accepts .git directory or file-based worktree)
        if (!self::isGitRepositoryPath($realPath)) {
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

            // Check rate limiting (per-command, generous for read-only operations)
            if (!self::checkRateLimit(get_current_user_id(), $command)) {
                return ['success' => false, 'output' => 'Rate limit exceeded. Please wait before making another request.', 'cmd' => $command];
            }

            // Validate inputs
            $repoPath      = self::validateRepoPath($repoPath);
            $sanitizedArgs = self::validateGitCommand($command, $args);

            // Build command
            $fullCommand = 'git -C ' . escapeshellarg($repoPath) . ' ' . $command;
            if ([] !== $sanitizedArgs) {
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
                            fclose($pipes[1]);
                            fclose($pipes[2]);
                            proc_terminate($process);
                            throw new \RuntimeException('Output size limit exceeded');
                        }
                    }
                }
            }

            // Check timeout
            if ((time() - $startTime) > self::MAX_EXECUTION_TIME) {
                fclose($pipes[1]);
                fclose($pipes[2]);
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
        $output = preg_replace('/(ghp_\w{36})/', '[masked_token]', $output);
        $output = preg_replace('/(gho_\w{36})/', '[masked_token]', $output);
        $output = preg_replace('/(ghu_\w{36})/', '[masked_token]', $output);
        $output = preg_replace('/(ghr_\w{36})/', '[masked_token]', $output);

        // Mask SSH keys and commit hashes (SHA-1 and SHA-256)
        // Use word boundaries to avoid masking parts of other strings
        $output = preg_replace('/\b([a-f0-9]{40})\b/', '[masked_hash]', $output);
        $output = preg_replace('/\b([a-f0-9]{64})\b/', '[masked_hash]', $output);

        // Mask URLs with credentials
        $output = preg_replace('#(https?://)([^:@\s]{2,}):([^@\s]{2,})@#', '$1$2:[masked_password]@', $output);

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

            $fullCommand = self::buildEnvPrefix($opts) . 'git -C ' . escapeshellarg($realDir) . ' ' . $gitArgs;
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

            $fullCommand = self::buildEnvPrefix($opts) . 'git ' . $gitArgs;
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
     * Execute a system-level ssh command.
     */
    public static function runSshCommand(string $sshArgs, array $opts = []): array
    {
        try {
            if (!GitManager::are_commands_enabled()) {
                return ['success' => false, 'output' => 'Command execution is disabled', 'cmd' => $sshArgs];
            }

            $fullCommand = self::buildEnvPrefix($opts) . $sshArgs;
            $result      = self::executeCommand($fullCommand);

            return [
                'success'        => (0 === $result['exit_code']),
                'output'         => $result['output'],
                'cmd'            => $sshArgs,
                'execution_time' => $result['execution_time'],
                'exit_code'      => $result['exit_code'],
            ];
        } catch (\Exception $exception) {
            return ['success' => false, 'output' => 'Command execution failed: ' . $exception->getMessage(), 'cmd' => $sshArgs];
        }
    }

    /**
     * Find a system executable using 'which' or 'where'.
     */
    public static function findExecutable(string $executable): array
    {
        try {
            if (!GitManager::are_commands_enabled()) {
                return ['success' => false, 'output' => 'Command execution is disabled'];
            }

            // Sanitize executable name to prevent command injection
            if (!preg_match('/^[a-zA-Z0-9_-]+$/', $executable)) {
                return ['success' => false, 'output' => 'Invalid executable name provided'];
            }

            $isWin   = ('WIN' === strtoupper(substr(PHP_OS, 0, 3)));
            $command = $isWin ? 'where ' . $executable : 'which ' . $executable;

            $result = self::executeCommand($command);

            return [
                'success'   => (0 === $result['exit_code']),
                'output'    => $result['output'],
                'cmd'       => $command,
                'exit_code' => $result['exit_code'],
            ];
        } catch (\Exception $exception) {
            return ['success' => false, 'output' => 'Command execution failed: ' . $exception->getMessage()];
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

            // Check if target directory already exists
            if (is_dir($targetDirectory)) {
                // Check if directory is empty
                $files = scandir($targetDirectory);
                $isEmpty = count($files) <= 2; // Only '.' and '..' entries

                if (!$isEmpty) {
                    return ['success' => false, 'output' => 'Destination path already exists and is not empty: ' . $targetDirectory, 'cmd' => 'clone'];
                }

                // Directory exists but is empty, remove it to allow clone
                if (!wp_rmdir($targetDirectory)) {
                    return ['success' => false, 'output' => 'Failed to remove existing empty directory: ' . $targetDirectory, 'cmd' => 'clone'];
                }
            }

            $envPrefix = self::buildEnvPrefix($opts);
            $cmd       = $envPrefix . 'git clone ' . escapeshellarg($remoteUrl) . ' ' . escapeshellarg($targetDirectory);
            $result    = self::executeCommand($cmd);

            $repoPath  = rtrim($targetDirectory, '\\/');
            $success   = (0 === $result['exit_code']) && self::isGitRepositoryPath($repoPath);

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
     * Determine if a path represents a Git repository.
     * Accepts both classic ".git" directory and file-based worktree layouts where ".git" is a file.
     */
    public static function isGitRepositoryPath(string $path): bool
    {
        $path = rtrim($path, '\\/');
        if ('' === $path || '0' === $path) {
            return false;
        }

        // 1) Fast checks: .git directory or .git file exists
        if (is_dir($path . '/.git')) {
            return true;
        }

        if (is_file($path . '/.git')) {
            // Some worktrees store a file containing "gitdir: <actual path>"
            $contents = @file_get_contents($path . '/.git');
            if (false !== $contents && preg_match('/^gitdir:\s*(.+)$/mi', (string) $contents)) {
                return true;
            }
        }

        // 2) Fallback: ask git if this is inside a work tree
        $probe = self::runInDirectory($path, 'rev-parse --is-inside-work-tree');
        if ($probe['success']) {
            $out = strtolower(trim((string) ($probe['output'] ?? '')));
            return ('true' === $out);
        }

        return false;
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
        $prefix    = '';
        $isWin     = ('WIN' === strtoupper(substr(PHP_OS, 0, 3)));

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
                @chmod($keyPath, 0600);
            }

            $wrapper = $tmpDir . '/ssh_wrapper_' . md5($keyPath) . ($isWin ? '.bat' : '.sh');

            if ($isWin) {
                if (!file_exists($wrapper)) {
                    file_put_contents($wrapper, "@echo off\nssh -i \"{$keyPath}\" -o StrictHostKeyChecking=no -o UserKnownHostsFile=nul %*\n");
                }
                $prefix .= 'set "GIT_SSH=' . $wrapper . '" && ';
            } else {
                if (!file_exists($wrapper)) {
                    file_put_contents($wrapper, "#!/bin/sh\nexec ssh -i '" . $keyPath . "' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \"$@\"\n");
                    @chmod($wrapper, 0755);
                }
                $prefix .= 'GIT_SSH=' . escapeshellarg($wrapper) . ' ';

                // Register cleanup for wrapper and key
                register_shutdown_function(function () use ($wrapper, $keyPath) {
                    if (file_exists($wrapper)) {
                        @unlink($wrapper);
                    }
                    // Consider if key should be deleted if it's meant to be persistent
                    // If key is truly temporary, uncomment below
                    // if (file_exists($keyPath)) {
                    //     @unlink($keyPath);
                    // }
                });
            }
        }

        // Ensure HOME is set for Git. When missing, try to find a real user home, otherwise use a safe fallback.
        $existingHome = getenv('HOME');
        if (empty($existingHome) || '0' === (string) $existingHome) {
            $homeToSet = '';

            // 1. Try to find a plausible existing home directory with a .gitconfig file
            $candidateHomes = self::candidateUserHomes();
            foreach ($candidateHomes as $candidate) {
                if (is_file($candidate . DIRECTORY_SEPARATOR . '.gitconfig')) {
                    $homeToSet = $candidate;
                    break;
                }
            }

            // 2. If no existing .gitconfig is found, use a safe fallback directory
            if ('' === $homeToSet) {
                $uploads      = function_exists('wp_upload_dir') ? wp_upload_dir(null, false) : null;
                $baseDir      = is_array($uploads) && !empty($uploads['basedir']) ? rtrim($uploads['basedir'], '\/') : WP_CONTENT_DIR;
                $fallbackHome = $baseDir . '/repo-manager-home';
                if (!is_dir($fallbackHome)) {
                    if (function_exists('wp_mkdir_p')) {
                        @wp_mkdir_p($fallbackHome);
                    } else {
                        @mkdir($fallbackHome, 0755, true);
                    }
                }
                $homeToSet = $fallbackHome;
            }

            if ($isWin) {
                $homeClean = str_replace('"', '', $homeToSet);
                $prefix = 'set "HOME=' . $homeClean . '" && ' . $prefix;
            } else {
                $prefix = 'HOME=' . escapeshellarg($homeToSet) . ' ' . $prefix;
            }
        }

        return $prefix;
    }

    /**
     * Candidate user home directories to probe for .gitconfig (Windows and Unix-like).
     */
    private static function candidateUserHomes(): array
    {
        $homes = [];
        // Standard environment variables
        $envHome = getenv('HOME');
        if (!empty($envHome) && '0' !== $envHome) {
            $homes[] = $envHome;
        }
        $userProfile = getenv('USERPROFILE');
        if (!empty($userProfile) && '0' !== $userProfile) {
            $homes[] = $userProfile;
        }
        // Windows specific composition
        $homeDrive  = getenv('HOMEDRIVE');
        $homePath   = getenv('HOMEPATH');
        if ($homeDrive && $homePath) {
            $homes[] = rtrim($homeDrive, '\\/') . rtrim($homePath, '\\/');
        }
        // De-duplicate and filter empty values
        return array_values(array_unique(array_filter($homes)));
    }

    /**
     * Fix repository file permissions for common issues.
     */
    public static function fixRepositoryPermissions(string $repoPath): array
    {
        try {
            if (!GitManager::are_commands_enabled()) {
                return ['success' => false, 'output' => 'Command execution is disabled'];
            }

            $realPath = self::validateRepoPath($repoPath); // This will validate it's a git repo inside wp-content

            // Using find is safer than wildcards and handles subdirectory permissions correctly
            $commands = [
                'chmod -R 755 ' . escapeshellarg($realPath),
                'find ' . escapeshellarg($realPath . '/.git/objects') . ' -type f -exec chmod 644 {} +',
                'find ' . escapeshellarg($realPath . '/.git/hooks') . ' -type f -exec chmod 755 {} +',
            ];

            // These files must exist and need specific permissions
            $filesToChmod = [
                $realPath . '/.git/config' => '644',
                $realPath . '/.git/HEAD'   => '644',
            ];

            foreach ($filesToChmod as $file => $mode) {
                if (file_exists($file)) {
                    $commands[] = 'chmod ' . escapeshellarg($mode) . ' ' . escapeshellarg($file);
                }
            }

            $results        = [];
            $overallSuccess = true;

            foreach ($commands as $cmd) {
                $result    = self::executeCommand($cmd);
                $isSuccess = ($result['exit_code'] === 0);
                $results[] = [
                    'command' => $cmd,
                    'success' => $isSuccess,
                    'output'  => $result['output'],
                ];
                if (!$isSuccess) {
                    $overallSuccess = false;
                }
            }

            return ['success' => $overallSuccess, 'details' => $results];

        } catch (\Exception $e) {
            return ['success' => false, 'output' => 'Permission fix failed: ' . $e->getMessage()];
        }
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
        $limits = get_option(self::RATE_LIMIT_OPTION, []);
        $now    = time();

        // Aggregate per-command budgets for this user (best-effort overview)
        $totals = [
            'current_requests'   => 0,
            'max_requests'       => 0,
            'window_seconds'     => self::DEFAULT_RATE_LIMIT_WINDOW,
            'remaining_requests' => 0,
        ];

        foreach ($limits as $key => $timestamps) {
            if (0 !== strpos((string) $key, $userId . ':')) {
                continue;
            }

            $command       = substr((string) $key, strlen((string) $userId) + 1);
            $config        = self::getRateLimitConfigForCommand($command);
            $windowStart   = $now - (int) $config['window'];
            $recent        = array_filter((array) $timestamps, fn ($t) => $t > $windowStart);
            $current       = count($recent);

            $totals['current_requests']   += $current;
            $totals['max_requests']       += (int) $config['max'];
        }

        $totals['remaining_requests'] = max(0, (int) $totals['max_requests'] - (int) $totals['current_requests']);

        return $totals;
    }
}
