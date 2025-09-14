<?php

namespace WPGitManager\Service;

use WPGitManager\Admin\GitManager;

if (! defined('ABSPATH')) {
    exit;
}

class GitCommandRunner
{
    /**
     * Allowed Git commands for security
     */
    private static $allowedCommands = [
        'status', 'log', 'branch', 'checkout', 'pull', 'push', 'fetch', 'clone',
        'config', 'remote', 'add', 'commit', 'diff', 'show', 'ls-remote',
        'rev-parse', 'rev-list', 'symbolic-ref', 'describe', 'tag', 'merge', 'rebase',
    ];

    /**
     * Validate and sanitize Git arguments
     */
    private static function validateGitArgs(string $gitArgs): string
    {
        // Remove any potential command injection attempts
        $gitArgs = preg_replace('/[;&|`$(){}]/', '', $gitArgs);

        // Extract the main command
        $parts   = explode(' ', trim($gitArgs), 2);
        $command = $parts[0] ?? '';

        // Check if command is in allowed list
        if (!in_array($command, self::$allowedCommands)) {
            $safeCmd = function_exists('sanitize_text_field') ? sanitize_text_field($command) : $command;
            throw new \InvalidArgumentException(sprintf("Command '%s' is not allowed", esc_html($safeCmd)));
        }

        return $gitArgs;
    }

    /**
     * Validate repository path
     */
    private static function validateRepoPath(string $repoPath): string
    {
        $repoPath = rtrim($repoPath, '\\/');

        // Ensure path is within WordPress installation
        $wpContentDir = WP_CONTENT_DIR;
        if (0 !== strpos(realpath($repoPath), (string) realpath($wpContentDir))) {
            throw new \InvalidArgumentException('Repository path must be within WordPress content directory');
        }

        // Check if it's a valid directory
        if (!is_dir($repoPath)) {
            throw new \InvalidArgumentException('Repository path does not exist');
        }

        return $repoPath;
    }

    public static function run(string $repoPath, string $gitArgs, array $opts = []): array
    {
        try {
            if (! GitManager::are_commands_enabled()) {
                return ['success' => false, 'output' => 'Command execution is disabled', 'cmd' => $gitArgs];
            }

            // Validate inputs
            $repoPath = self::validateRepoPath($repoPath);
            $gitArgs  = self::validateGitArgs($gitArgs);

            if (! is_dir($repoPath . '/.git')) {
                return ['success' => false, 'output' => 'Not a git repository'];
            }
        } catch (\InvalidArgumentException $invalidArgumentException) {
            return ['success' => false, 'output' => $invalidArgumentException->getMessage(), 'cmd' => $gitArgs];
        }

        $home           = getenv('HOME') ?: (getenv('USERPROFILE') ?: sys_get_temp_dir());
        $homeClean      = str_replace('"', '', $home);
        $pathClean      = str_replace('"', '', $repoPath);
        $envPrefix      = '';
        $sshWrapperFile = null;
        if (! empty($opts['ssh_key'])) {
            $keyContent = $opts['ssh_key'];
            $tmpDir     = wp_upload_dir(null, false)['basedir'] . '/repo-manager-keys';
            if (! is_dir($tmpDir)) {
                @wp_mkdir_p($tmpDir);
            }

            $keyPath = $tmpDir . '/key_' . md5($keyContent) . '.pem';
            if (! file_exists($keyPath)) {
                file_put_contents($keyPath, $keyContent);
            }

            $wrapper = $tmpDir . '/ssh_wrapper_' . md5($keyPath) . ('WIN' === strtoupper(substr(PHP_OS, 0, 3)) ? '.bat' : '.sh');
            if ('WIN' === strtoupper(substr(PHP_OS, 0, 3))) {
                if (! file_exists($wrapper)) {
                    file_put_contents($wrapper, "@echo off\nssh -i \"{$keyPath}\" -o StrictHostKeyChecking=no %*\n");
                }
            } elseif (! file_exists($wrapper)) {
                file_put_contents($wrapper, "#!/bin/sh\nexec ssh -i '{$keyPath}' -o StrictHostKeyChecking=no \"$@\"\n");
            }

            $sshWrapperFile = $wrapper;
        }

        if ($sshWrapperFile) {
            if ('WIN' === strtoupper(substr(PHP_OS, 0, 3))) {
                $envPrefix .= 'set "GIT_SSH=' . $sshWrapperFile . '" && ';
            } else {
                $envPrefix .= 'GIT_SSH=' . escapeshellarg($sshWrapperFile) . ' ';
            }
        }

        // Allow caller to request lower priority execution on slow hosts
        // On *nix, we can use nice; on Windows, we keep synchronous execution to capture output
        $nicePrefix = '';
        if (! empty($opts['low_priority']) && 'WIN' !== strtoupper(substr(PHP_OS, 0, 3))) {
            $nicePrefix = 'nice -n 10 ';
        }

        if ('WIN' === strtoupper(substr(PHP_OS, 0, 3))) {
            $cmd = 'set "HOME=' . $homeClean . '" && ' . $envPrefix . $nicePrefix . 'git -C "' . $pathClean . '" ' . $gitArgs . ' 2>&1';
        } else {
            $cmd = $envPrefix . 'HOME=' . escapeshellarg($home) . ' ' . $nicePrefix . 'git -C ' . escapeshellarg($repoPath) . ' ' . $gitArgs . ' 2>&1';
        }

        // Execute with timeout and additional security
        $result = self::executeCommand($cmd);

        $output   = null;
        $exitCode = null;
        if (null !== $result) {
            $output   = $result['output'] ?? '';
            $exitCode = $result['exit_code'] ?? null;

            // Mask sensitive info
            $output = preg_replace('/(ghp_\w{36})/', '[masked]', $output);
            $output = preg_replace('/(gho_\w{36})/', '[masked]', $output);
            $output = preg_replace('/(ghu_\w{36})/', '[masked]', $output);
            $output = preg_replace('/(ghr_\w{36})/', '[masked]', $output);
            $output = preg_replace('/([A-Za-z0-9]{40})/', '[masked]', $output);
            $output = preg_replace('/([A-Za-z0-9]{64})/', '[masked]', $output);
            $output = preg_replace('#(https?://)([^:@\s]{2,}):([^@\s]{2,})@#', '$1$2:[masked]@', $output);
        }

        return [
            'success'   => (0 === (int) $exitCode),
            'output'    => $output,
            'cmd'       => $gitArgs,
            'exit_code' => $exitCode,
        ];
    }

    /**
     * Execute command with additional security measures and improved timeout handling
     */
    private static function executeCommand(string $cmd): ?array
    {
        // Set execution time limit based on command type
        $maxExecutionTime = self::getCommandTimeout($cmd);
        $startTime        = time();

        // Use proc_open for better control and timeout handling
        $descriptorspec = [
            0 => ['pipe', 'r'],  // stdin
            1 => ['pipe', 'w'],  // stdout
            2 => ['pipe', 'w'],   // stderr
        ];

        // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found -- Using proc_open for controlled subprocess with timeout
        $process = proc_open($cmd, $descriptorspec, $pipes);

        if (!is_resource($process)) {
            return null;
        }

        // Close stdin
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- closing process pipe
        fclose($pipes[0]);

        // Set non-blocking mode
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $output       = '';
        $error        = '';
        $lastActivity = time();

        // Read output with timeout
        while (true) {
            $read   = [$pipes[1], $pipes[2]];
            $write  = null;
            $except = null;

            $ready = stream_select($read, $write, $except, 1); // 1 second timeout

            if (false === $ready) {
                break;
            }

            if ($ready > 0) {
                foreach ($read as $pipe) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- reading process pipe
                    $data = fread($pipe, 8192);
                    if (false !== $data && '' !== $data) {
                        $lastActivity = time(); // Update activity timestamp
                        if ($pipe === $pipes[1]) {
                            $output .= $data;
                        } else {
                            $error .= $data;
                        }
                    }
                }
            }

            // Check timeout - both total time and inactivity time
            $currentTime = time();
            if (($currentTime - $startTime) > $maxExecutionTime) {
                proc_terminate($process);
                break;
            }

            // Check for inactivity timeout (no output for 10 seconds)
            if (($currentTime - $lastActivity) > 10) {
                proc_terminate($process);
                break;
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

        // Return structured result
        return [
            'output'    => ($output !== '' ? $output : $error),
            'exit_code' => $exitCode,
        ];
    }

    /**
     * Get appropriate timeout for different git commands
     */
    private static function getCommandTimeout(string $cmd): int
    {
        // Commands that might take longer
        if (false !== strpos($cmd, 'fetch') || false !== strpos($cmd, 'clone')) {
            return 60; // 1 minute for network operations
        }

        if (false !== strpos($cmd, 'log')) {
            return 20; // 20 seconds for log operations
        }

        if (false !== strpos($cmd, 'status') || false !== strpos($cmd, 'branch')) {
            return 10; // 10 seconds for status/branch operations
        }

        return 15; // Default 15 seconds for other operations
    }
}
