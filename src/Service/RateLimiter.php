<?php

namespace WPGitManager\Service;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Advanced rate limiting system for Repo Manager
 */
class RateLimiter
{
    private const RATE_LIMIT_OPTION = 'git_manager_rate_limits';

    private const RATE_LIMIT_KEYS_OPTION = 'git_manager_rate_limit_keys';

    private static ?self $instance = null;

    public static function instance(): self
    {
        if (!self::$instance instanceof \WPGitManager\Service\RateLimiter) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    private function __construct()
    {
        $this->cleanupExpiredLimits();
    }

    /**
     * Check if request is allowed
     */
    public function isAllowed(string $identifier, string $action = 'default', ?int $maxRequests = null, ?int $windowSeconds = null): bool
    {
        if (null === $maxRequests) {
            $maxRequests = Configuration::get('security.rate_limit_max_requests', 10);
        }

        if (null === $windowSeconds) {
            $windowSeconds = Configuration::get('security.rate_limit_window', 60);
        }

        $key         = $this->generateKey($identifier, $action);
        $currentTime = time();
        $windowStart = $currentTime - $windowSeconds;

        // Get existing limits
        $limits     = get_option(self::RATE_LIMIT_OPTION, []);
        $userLimits = $limits[$key] ?? [];

        // Clean old entries
        $userLimits = array_filter($userLimits, fn ($timestamp) => $timestamp > $windowStart);

        // Check if limit exceeded
        if (count($userLimits) >= $maxRequests) {
            $this->logRateLimitExceeded($identifier, $action, count($userLimits), $maxRequests);
            return false;
        }

        // Add current request
        $userLimits[] = $currentTime;
        $limits[$key] = $userLimits;

        update_option(self::RATE_LIMIT_OPTION, $limits, false);

        return true;
    }

    /**
     * Get remaining requests for identifier
     */
    public function getRemainingRequests(string $identifier, string $action = 'default', ?int $maxRequests = null, ?int $windowSeconds = null): int
    {
        if (null === $maxRequests) {
            $maxRequests = Configuration::get('security.rate_limit_max_requests', 10);
        }

        if (null === $windowSeconds) {
            $windowSeconds = Configuration::get('security.rate_limit_window', 60);
        }

        $key         = $this->generateKey($identifier, $action);
        $currentTime = time();
        $windowStart = $currentTime - $windowSeconds;

        $limits     = get_option(self::RATE_LIMIT_OPTION, []);
        $userLimits = $limits[$key] ?? [];

        // Clean old entries
        $userLimits = array_filter($userLimits, fn ($timestamp) => $timestamp > $windowStart);

        return max(0, $maxRequests - count($userLimits));
    }

    /**
     * Get rate limit status
     */
    public function getStatus(string $identifier, string $action = 'default'): array
    {
        $maxRequests   = Configuration::get('security.rate_limit_max_requests', 10);
        $windowSeconds = Configuration::get('security.rate_limit_window', 60);

        $remaining   = $this->getRemainingRequests($identifier, $action, $maxRequests, $windowSeconds);
        $currentTime = time();
        $windowStart = $currentTime - $windowSeconds;

        $key        = $this->generateKey($identifier, $action);
        $limits     = get_option(self::RATE_LIMIT_OPTION, []);
        $userLimits = $limits[$key] ?? [];

        // Clean old entries
        $userLimits = array_filter($userLimits, fn ($timestamp) => $timestamp > $windowStart);

        $nextReset = null;
        if ([] !== $userLimits) {
            $oldestRequest = min($userLimits);
            $nextReset     = $oldestRequest + $windowSeconds;
        }

        return [
            'identifier'         => $identifier,
            'action'             => $action,
            'current_requests'   => count($userLimits),
            'max_requests'       => $maxRequests,
            'remaining_requests' => $remaining,
            'window_seconds'     => $windowSeconds,
            'next_reset'         => $nextReset,
            'is_limited'         => count($userLimits) >= $maxRequests,
        ];
    }

    /**
     * Reset rate limit for identifier
     */
    public function reset(string $identifier, string $action = 'default'): bool
    {
        $key    = $this->generateKey($identifier, $action);
        $limits = get_option(self::RATE_LIMIT_OPTION, []);

        if (isset($limits[$key])) {
            unset($limits[$key]);
            update_option(self::RATE_LIMIT_OPTION, $limits, false);
            return true;
        }

        return false;
    }

    /**
     * Clear all rate limits
     */
    public function clearAll(): void
    {
        delete_option(self::RATE_LIMIT_OPTION);
        delete_option(self::RATE_LIMIT_KEYS_OPTION);
    }

    /**
     * Get rate limit statistics
     */
    public function getStats(): array
    {
        $limits        = get_option(self::RATE_LIMIT_OPTION, []);
        $currentTime   = time();
        $windowSeconds = Configuration::get('security.rate_limit_window', 60);
        $windowStart   = $currentTime - $windowSeconds;

        $stats = [
            'total_identifiers'   => 0,
            'active_identifiers'  => 0,
            'limited_identifiers' => 0,
            'total_requests'      => 0,
            'by_action'           => [],
        ];

        foreach ($limits as $key => $userLimits) {
            $stats['total_identifiers']++;

            // Clean old entries
            $activeLimits = array_filter($userLimits, fn ($timestamp) => $timestamp > $windowStart);

            if ([] !== $activeLimits) {
                $stats['active_identifiers']++;
                $stats['total_requests'] += count($activeLimits);

                // Check if limited
                $maxRequests = Configuration::get('security.rate_limit_max_requests', 10);
                if (count($activeLimits) >= $maxRequests) {
                    $stats['limited_identifiers']++;
                }

                // Count by action
                $action                      = $this->extractActionFromKey($key);
                $stats['by_action'][$action] = ($stats['by_action'][$action] ?? 0) + 1;
            }
        }

        return $stats;
    }

    /**
     * Clear all rate limit data
     */
    public function clearAllRateLimits(): void
    {
        delete_option(self::RATE_LIMIT_OPTION);
    }

    /**
     * Apply rate limiting to AJAX request
     */
    public function checkAjaxRateLimit(string $action): bool
    {
        $userId     = get_current_user_id();
        $identifier = $this->getUserIdentifier($userId);

        // Different limits for different actions
        $actionLimits = [
            'git_manager_repo_clone'  => ['max' => 3, 'window' => 300], // 3 clones per 5 minutes
            'git_manager_repo_delete' => ['max' => 5, 'window' => 300], // 5 deletes per 5 minutes
            'git_manager_pull'        => ['max' => 20, 'window' => 60], // 20 pulls per minute
            'git_manager_push'        => ['max' => 10, 'window' => 60], // 10 pushes per minute
            'git_manager_fetch'       => ['max' => 30, 'window' => 60], // 30 fetches per minute
            'git_manager_get_branches' => ['max' => 50, 'window' => 60], // 50 branch requests per minute
            'git_manager_bulk_repo_status' => ['max' => 100, 'window' => 60], // 100 status requests per minute
        ];

        $limits = $actionLimits[$action] ?? null;

        if ($limits) {
            return $this->isAllowed($identifier, $action, $limits['max'], $limits['window']);
        }

        // Default rate limiting
        return $this->isAllowed($identifier, $action);
    }

    /**
     * Get user identifier for rate limiting
     */
    private function getUserIdentifier(int $userId): string
    {
        $user = get_userdata($userId);
        if (!$user) {
            $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';
            return 'anonymous_' . $ip;
        }

        return 'user_' . $userId . '_' . md5($user->user_login);
    }

    /**
     * Generate rate limit key
     */
    private function generateKey(string $identifier, string $action): string
    {
        return md5($identifier . '_' . $action);
    }

    /**
     * Extract action from key (for statistics)
     */
    private function extractActionFromKey(string $key): string
    {
        $keys = get_option(self::RATE_LIMIT_KEYS_OPTION, []);
        return $keys[$key] ?? 'unknown';
    }

    /**
     * Log rate limit exceeded event
     */
    private function logRateLimitExceeded(string $identifier, string $action, int $currentRequests, int $maxRequests): void
    {
        $logger = AuditLogger::instance();
        $logger->logSecurityEvent('rate_limit_exceeded', [
            'identifier'       => $identifier,
            'action'           => $action,
            'current_requests' => $currentRequests,
            'max_requests'     => $maxRequests,
            'user_id'          => get_current_user_id(),
        ]);
    }

    /**
     * Cleanup expired rate limits
     */
    private function cleanupExpiredLimits(): void
    {
        $limits        = get_option(self::RATE_LIMIT_OPTION, []);
        $currentTime   = time();
        $windowSeconds = Configuration::get('security.rate_limit_window', 60);
        $windowStart   = $currentTime - $windowSeconds;
        $cleaned       = 0;

        foreach ($limits as $key => $userLimits) {
            $activeLimits = array_filter($userLimits, fn ($timestamp) => $timestamp > $windowStart);

            if ([] === $activeLimits) {
                unset($limits[$key]);
                $cleaned++;
            } else {
                $limits[$key] = array_values($activeLimits);
            }
        }

        if ($cleaned > 0) {
            update_option(self::RATE_LIMIT_OPTION, $limits, false);
        }
    }

    /**
     * Get rate limit recommendations
     */
    public function getRecommendations(): array
    {
        $stats           = $this->getStats();
        $recommendations = [];

        if ($stats['limited_identifiers'] > 0) {
            $percentage = ($stats['limited_identifiers'] / max(1, $stats['active_identifiers'])) * 100;

            if ($percentage > 20) {
                $recommendations[] = 'High rate limiting activity detected. Consider increasing limits or investigating usage patterns.';
            }
        }

        if ($stats['total_requests'] > 1000) {
            $recommendations[] = 'High request volume detected. Consider implementing additional caching.';
        }

        return $recommendations;
    }

    /**
     * Whitelist identifier (bypass rate limiting)
     */
    public function whitelist(string $identifier): void
    {
        $whitelist   = get_option('git_manager_rate_limit_whitelist', []);
        $whitelist[] = $identifier;
        $whitelist   = array_unique($whitelist);
        update_option('git_manager_rate_limit_whitelist', $whitelist, false);
    }

    /**
     * Remove from whitelist
     */
    public function removeFromWhitelist(string $identifier): void
    {
        $whitelist = get_option('git_manager_rate_limit_whitelist', []);
        $whitelist = array_filter($whitelist, fn ($item) => $item !== $identifier);
        update_option('git_manager_rate_limit_whitelist', array_values($whitelist), false);
    }

    /**
     * Check if identifier is whitelisted
     */
    public function isWhitelisted(string $identifier): bool
    {
        $whitelist = get_option('git_manager_rate_limit_whitelist', []);
        return in_array($identifier, $whitelist);
    }
}
