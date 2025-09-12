<?php

namespace WPGitManager\Service;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Comprehensive audit logging system for Repo Manager
 */
class AuditLogger
{
    private const LOG_OPTION = 'git_manager_audit_logs';

    private const LOG_LEVELS = [
        'debug'   => 0,
        'info'    => 1,
        'warning' => 2,
        'error'   => 3,
    ];

    private static ?self $instance = null;

    public static function instance(): self
    {
        if (!self::$instance instanceof \WPGitManager\Service\AuditLogger) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    private function __construct()
    {
        $this->cleanupOldLogs();
    }

    /**
     * Log an event
     */
    public function log(string $level, string $action, array $context = []): void
    {
        if (!Configuration::get('logging.enabled', true)) {
            return;
        }

        $minLevel = Configuration::get('logging.level', 'info');
        if (self::LOG_LEVELS[$level] < self::LOG_LEVELS[$minLevel]) {
            return;
        }

        $logEntry = [
            'id'         => uniqid('log_', true),
            'timestamp'  => current_time('mysql'),
            'level'      => $level,
            'action'     => $action,
            'user_id'    => get_current_user_id(),
            'user_login' => wp_get_current_user()->user_login ?? 'system',
            'ip_address' => $this->getClientIp(),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'unknown',
            'context'    => $this->sanitizeContext($context),
            'session_id' => session_id() ?: 'unknown',
        ];

        $this->storeLog($logEntry);
    }

    /**
     * Log Git command execution
     */
    public function logGitCommand(string $command, string $repoPath, bool $success, ?string $error = null, array $additionalContext = []): void
    {
        $context = array_merge([
            'command'   => $command,
            'repo_path' => $repoPath,
            'success'   => $success,
            'error'     => $error,
        ], $additionalContext);

        $level = $success ? 'info' : 'error';
        $this->log($level, 'git_command_executed', $context);
    }

    /**
     * Log repository operations
     */
    public function logRepositoryOperation(string $operation, string $repoId, array $context = []): void
    {
        $context = array_merge([
            'repo_id'   => $repoId,
            'operation' => $operation,
        ], $context);

        $this->log('info', 'repository_operation', $context);
    }

    /**
     * Log security events
     */
    public function logSecurityEvent(string $event, array $context = []): void
    {
        $context = array_merge([
            'security_event' => $event,
        ], $context);

        $this->log('warning', 'security_event', $context);
    }

    /**
     * Log authentication events
     */
    public function logAuthEvent(string $event, array $context = []): void
    {
        $context = array_merge([
            'auth_event' => $event,
        ], $context);

        $this->log('info', 'authentication_event', $context);
    }

    /**
     * Log configuration changes
     */
    public function logConfigChange(string $setting, $oldValue, $newValue): void
    {
        $this->log('info', 'configuration_changed', [
            'setting'   => $setting,
            'old_value' => $this->maskSensitiveValue($setting, $oldValue),
            'new_value' => $this->maskSensitiveValue($setting, $newValue),
        ]);
    }

    /**
     * Log performance metrics
     */
    public function logPerformance(string $operation, float $executionTime, array $context = []): void
    {
        if (!Configuration::get('logging.performance_logging', false)) {
            return;
        }

        $context = array_merge([
            'operation'      => $operation,
            'execution_time' => $executionTime,
        ], $context);

        $this->log('debug', 'performance_metric', $context);
    }

    /**
     * Get logs with filtering
     */
    public function getLogs(array $filters = [], int $limit = 100, int $offset = 0): array
    {
        $logs = get_option(self::LOG_OPTION, []);

        // Apply filters
        if ($filters !== []) {
            $logs = array_filter($logs, function ($log) use ($filters) {
                foreach ($filters as $key => $value) {
                    if (isset($log[$key]) && $log[$key] !== $value) {
                        return false;
                    }
                }

                return true;
            });
        }

        // Sort by timestamp (newest first)
        usort($logs, fn($a, $b) => strtotime($b['timestamp']) - strtotime($a['timestamp']));

        return array_slice($logs, $offset, $limit);
    }

    /**
     * Get log statistics
     */
    public function getStats(): array
    {
        $logs  = get_option(self::LOG_OPTION, []);
        $stats = [
            'total_logs'      => count($logs),
            'by_level'        => [],
            'by_action'       => [],
            'by_user'         => [],
            'recent_activity' => 0,
        ];

        $oneDayAgo = strtotime('-1 day');

        foreach ($logs as $log) {
            // Count by level
            $level                     = $log['level'] ?? 'unknown';
            $stats['by_level'][$level] = ($stats['by_level'][$level] ?? 0) + 1;

            // Count by action
            $action                      = $log['action'] ?? 'unknown';
            $stats['by_action'][$action] = ($stats['by_action'][$action] ?? 0) + 1;

            // Count by user
            $user                    = $log['user_login'] ?? 'unknown';
            $stats['by_user'][$user] = ($stats['by_user'][$user] ?? 0) + 1;

            // Count recent activity
            if (strtotime($log['timestamp']) > $oneDayAgo) {
                $stats['recent_activity']++;
            }
        }

        return $stats;
    }

    /**
     * Export logs
     */
    public function export(array $filters = [], string $format = 'json'): string
    {
        $logs = $this->getLogs($filters, 10000); // Large limit for export

        switch ($format) {
            case 'csv':
                return $this->exportToCsv($logs);
            case 'json':
            default:
                return json_encode([
                    'exported_at' => current_time('mysql'),
                    'filters'     => $filters,
                    'total_logs'  => count($logs),
                    'logs'        => $logs,
                ], JSON_PRETTY_PRINT);
        }
    }

    /**
     * Clear old logs
     */
    public function clearOldLogs(int $daysToKeep = null): int
    {
        if (null === $daysToKeep) {
            $daysToKeep = Configuration::get('logging.log_retention_days', 30);
        }

        $logs       = get_option(self::LOG_OPTION, []);
        $cutoffTime = strtotime(sprintf('-%s days', $daysToKeep));
        $cleaned    = 0;

        $logs = array_filter($logs, function ($log) use ($cutoffTime, &$cleaned) {
            $logTime = strtotime($log['timestamp']);
            if ($logTime < $cutoffTime) {
                $cleaned++;
                return false;
            }

            return true;
        });

        update_option(self::LOG_OPTION, array_values($logs), false);
        return $cleaned;
    }

    /**
     * Clear all logs
     */
    public function clearAllLogs(): void
    {
        delete_option(self::LOG_OPTION);
    }

    /**
     * Get security alerts
     */
    public function getSecurityAlerts(int $hours = 24): array
    {
        $cutoffTime = strtotime(sprintf('-%d hours', $hours));
        $logs       = get_option(self::LOG_OPTION, []);

        return array_filter($logs, fn($log) => 'warning' === $log['level'] && 'security_event' === $log['action'] && strtotime($log['timestamp']) > $cutoffTime);
    }

    /**
     * Get user activity summary
     */
    public function getUserActivity(int $userId, int $days = 7): array
    {
        $cutoffTime = strtotime(sprintf('-%d days', $days));
        $logs       = get_option(self::LOG_OPTION, []);

        $userLogs = array_filter($logs, fn($log) => $log['user_id'] == $userId && strtotime($log['timestamp']) > $cutoffTime);

        $activity = [
            'total_actions'   => count($userLogs),
            'actions_by_type' => [],
            'recent_actions'  => array_slice($userLogs, 0, 10),
        ];

        foreach ($userLogs as $log) {
            $action                               = $log['action'] ?? 'unknown';
            $activity['actions_by_type'][$action] = ($activity['actions_by_type'][$action] ?? 0) + 1;
        }

        return $activity;
    }

    /**
     * Store log entry
     */
    private function storeLog(array $logEntry): void
    {
        $logs   = get_option(self::LOG_OPTION, []);
        $logs[] = $logEntry;

        // Limit total logs
        $maxLogs = Configuration::get('logging.max_log_entries', 1000);
        if (count($logs) > $maxLogs) {
            $logs = array_slice($logs, -$maxLogs);
        }

        update_option(self::LOG_OPTION, $logs, false);
    }

    /**
     * Sanitize context data
     */
    private function sanitizeContext(array $context): array
    {
        $sensitiveKeys = ['password', 'token', 'private_key', 'secret', 'key'];

        foreach ($context as $key => $value) {
            if (in_array(strtolower($key), $sensitiveKeys)) {
                $context[$key] = '[masked]';
            } elseif (is_string($value) && strlen($value) > 1000) {
                $context[$key] = substr($value, 0, 1000) . '...[truncated]';
            }
        }

        return $context;
    }

    /**
     * Mask sensitive values in configuration
     */
    private function maskSensitiveValue(string $setting, $value): string
    {
        $sensitiveSettings = ['webhook_secret', 'api_key', 'token'];

        if (in_array($setting, $sensitiveSettings)) {
            return '[masked]';
        }

        return is_string($value) ? $value : json_encode($value);
    }

    /**
     * Get client IP address
     */
    private function getClientIp(): string
    {
        $ipKeys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];

        foreach ($ipKeys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = sanitize_text_field(wp_unslash($_SERVER[$key]));
                if (false !== strpos($ip, ',')) {
                    $ip = trim(explode(',', $ip)[0]);
                }

                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- $_SERVER is sanitized below
        return sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    }

    /**
     * Export logs to CSV format
     */
    private function exportToCsv(array $logs): string
    {
        if ($logs === []) {
            return '';
        }

        // Use output buffering instead of direct fopen/fclose to satisfy WPCS
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $output = fopen('php://temp', 'r+');

        // Write header
        $headers = ['ID', 'Timestamp', 'Level', 'Action', 'User', 'IP Address', 'Context'];
        fputcsv($output, $headers);

        // Write data
        foreach ($logs as $log) {
            fputcsv($output, [
                $log['id'] ?? '',
                $log['timestamp'] ?? '',
                $log['level'] ?? '',
                $log['action'] ?? '',
                $log['user_login'] ?? '',
                $log['ip_address'] ?? '',
                json_encode($log['context'] ?? []),
            ]);
        }

        rewind($output);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
        $csv = stream_get_contents($output);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($output);

        return $csv;
    }

    /**
     * Cleanup old logs on initialization
     */
    private function cleanupOldLogs(): void
    {
        $retentionDays = Configuration::get('logging.log_retention_days', 30);
        $this->clearOldLogs($retentionDays);
    }
}
