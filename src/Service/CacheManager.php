<?php

namespace WPGitManager\Service;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Advanced caching system for Repo Manager
 */
class CacheManager
{
    private const CACHE_OPTION_PREFIX = 'git_manager_cache_';

    private const CACHE_META_OPTION   = 'git_manager_cache_meta';

    private static ?self $instance = null;

    private array $memoryCache     = [];

    private array $cacheStats      = [
        'hits'    => 0,
        'misses'  => 0,
        'sets'    => 0,
        'deletes' => 0,
    ];

    public static function instance(): self
    {
        if (!self::$instance instanceof \WPGitManager\Service\CacheManager) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    private function __construct()
    {
        $this->cleanupExpiredCache();
    }

    /**
     * Get cached data
     */
    public function get(string $key, $default = null)
    {
        // Check memory cache first
        if (isset($this->memoryCache[$key])) {
            $this->cacheStats['hits']++;
            return $this->memoryCache[$key];
        }

        // Check persistent cache
        $cacheKey = self::CACHE_OPTION_PREFIX . md5($key);
        $cached   = get_option($cacheKey, null);

        if (null === $cached) {
            $this->cacheStats['misses']++;
            return $default;
        }

        // Validate cache entry
        if (!$this->isValidCacheEntry($cached)) {
            $this->delete($key);
            $this->cacheStats['misses']++;
            return $default;
        }

        // Store in memory cache
        $this->memoryCache[$key] = $cached['data'];
        $this->cacheStats['hits']++;

        return $cached['data'];
    }

    /**
     * Set cached data
     */
    public function set(string $key, $data, ?int $ttl = null): bool
    {
        if (null === $ttl) {
            $ttl = Configuration::get('performance.cache_ttl', 300);
        }

        $cacheEntry = [
            'data'    => $data,
            'expires' => time() + $ttl,
            'created' => time(),
            'size'    => $this->calculateSize($data),
        ];

        // Store in memory cache
        $this->memoryCache[$key] = $data;

        // Store in persistent cache
        $cacheKey = self::CACHE_OPTION_PREFIX . md5($key);
        $result   = update_option($cacheKey, $cacheEntry, false);

        if ($result) {
            $this->updateCacheMeta($key, $cacheEntry);
            $this->cacheStats['sets']++;
        }

        return $result;
    }

    /**
     * Delete cached data
     */
    public function delete(string $key): bool
    {
        // Remove from memory cache
        unset($this->memoryCache[$key]);

        // Remove from persistent cache
        $cacheKey = self::CACHE_OPTION_PREFIX . md5($key);
        $result   = delete_option($cacheKey);

        if ($result) {
            $this->removeCacheMeta($key);
            $this->cacheStats['deletes']++;
        }

        return $result;
    }

    /**
     * Clear all cache
     */
    public function clear(): bool
    {
        $this->memoryCache = [];

        // Get all cache keys
        $meta = get_option(self::CACHE_META_OPTION, []);

        foreach ($meta as $key => $entry) {
            $cacheKey = self::CACHE_OPTION_PREFIX . md5($key);
            delete_option($cacheKey);
        }

        delete_option(self::CACHE_META_OPTION);

        return true;
    }

    /**
     * Get or set cached data with callback
     */
    public function remember(string $key, callable $callback, ?int $ttl = null)
    {
        $cached = $this->get($key);

        if (null !== $cached) {
            return $cached;
        }

        $data = $callback();
        $this->set($key, $data, $ttl);

        return $data;
    }

    /**
     * Cache Git command result
     */
    public function cacheGitResult(string $repoPath, string $command, array $args, callable $callback, ?int $ttl = null)
    {
        $key = $this->generateGitCacheKey($repoPath, $command, $args);

        return $this->remember($key, $callback, $ttl);
    }

    /**
     * Cache repository data
     */
    public function cacheRepositoryData(string $repoId, string $dataType, callable $callback, ?int $ttl = null)
    {
        $key = sprintf('repo_%s_%s', $repoId, $dataType);

        return $this->remember($key, $callback, $ttl);
    }

    /**
     * Invalidate repository cache
     */
    public function invalidateRepository(string $repoId): void
    {
        $meta = get_option(self::CACHE_META_OPTION, []);

        foreach ($meta as $key => $entry) {
            if (0 === strpos($key, sprintf('repo_%s_', $repoId))) {
                $this->delete($key);
            }
        }
    }

    /**
     * Get cache statistics
     */
    public function getStats(): array
    {
        $meta       = get_option(self::CACHE_META_OPTION, []);
        $totalSize  = 0;
        $entryCount = 0;

        foreach ($meta as $entry) {
            $totalSize += $entry['size'];
            $entryCount++;
        }

        return [
            'hits'     => $this->cacheStats['hits'],
            'misses'   => $this->cacheStats['misses'],
            'sets'     => $this->cacheStats['sets'],
            'deletes'  => $this->cacheStats['deletes'],
            'hit_rate' => $this->cacheStats['hits'] + $this->cacheStats['misses'] > 0
                ? round(($this->cacheStats['hits'] / ($this->cacheStats['hits'] + $this->cacheStats['misses'])) * 100, 2)
                : 0,
            'entry_count'    => $entryCount,
            'total_size'     => $totalSize,
            'memory_entries' => count($this->memoryCache),
        ];
    }

    /**
     * Cleanup expired cache entries
     */
    public function cleanupExpiredCache(): int
    {
        $meta        = get_option(self::CACHE_META_OPTION, []);
        $cleaned     = 0;
        $currentTime = time();

        foreach ($meta as $key => $entry) {
            if ($entry['expires'] < $currentTime) {
                $this->delete($key);
                $cleaned++;
            }
        }

        return $cleaned;
    }

    /**
     * Optimize cache (remove least recently used entries)
     */
    public function optimize(int $maxEntries = 1000): int
    {
        $meta = get_option(self::CACHE_META_OPTION, []);

        if (count($meta) <= $maxEntries) {
            return 0;
        }

        // Sort by creation time (oldest first)
        uasort($meta, fn($a, $b) => $a['created'] - $b['created']);

        $removed         = 0;
        $entriesToRemove = count($meta) - $maxEntries;

        foreach (array_keys($meta) as $key) {
            if ($removed >= $entriesToRemove) {
                break;
            }

            $this->delete($key);
            $removed++;
        }

        return $removed;
    }

    /**
     * Generate cache key for Git commands
     */
    private function generateGitCacheKey(string $repoPath, string $command, array $args): string
    {
        $normalizedPath    = realpath($repoPath) ?: $repoPath;
        $normalizedCommand = trim($command);
        $normalizedArgs    = array_map('trim', $args);

        return 'git_' . md5($normalizedPath . '_' . $normalizedCommand . '_' . implode('_', $normalizedArgs));
    }

    /**
     * Validate cache entry
     */
    private function isValidCacheEntry($cached): bool
    {
        if (!is_array($cached)) {
            return false;
        }

        if (!isset($cached['data'], $cached['expires'], $cached['created'])) {
            return false;
        }

        return $cached['expires'] > time();
    }

    /**
     * Calculate data size
     */
    private function calculateSize($data): int
    {
        return strlen(serialize($data));
    }

    /**
     * Update cache metadata
     */
    private function updateCacheMeta(string $key, array $entry): void
    {
        $meta       = get_option(self::CACHE_META_OPTION, []);
        $meta[$key] = $entry;
        update_option(self::CACHE_META_OPTION, $meta, false);
    }

    /**
     * Remove cache metadata
     */
    private function removeCacheMeta(string $key): void
    {
        $meta = get_option(self::CACHE_META_OPTION, []);
        unset($meta[$key]);
        update_option(self::CACHE_META_OPTION, $meta, false);
    }

    /**
     * Warm up cache with common data
     */
    public function warmUp(): void
    {
        // This can be called during plugin initialization
        // to pre-load commonly used data
    }

    /**
     * Get cache health status
     */
    public function getHealthStatus(): array
    {
        $stats  = $this->getStats();
        $health = 'good';

        if ($stats['hit_rate'] < 50) {
            $health = 'poor';
        } elseif ($stats['hit_rate'] < 70) {
            $health = 'fair';
        }

        return [
            'status'          => $health,
            'stats'           => $stats,
            'recommendations' => $this->getRecommendations($stats),
        ];
    }

    /**
     * Get cache optimization recommendations
     */
    private function getRecommendations(array $stats): array
    {
        $recommendations = [];

        if ($stats['hit_rate'] < 50) {
            $recommendations[] = 'Consider increasing cache TTL for better hit rate';
        }

        if ($stats['total_size'] > 10 * 1024 * 1024) { // 10MB
            $recommendations[] = 'Cache size is large, consider optimizing or reducing TTL';
        }

        if ($stats['entry_count'] > 1000) {
            $recommendations[] = 'Too many cache entries, consider cleanup';
        }

        return $recommendations;
    }
}
