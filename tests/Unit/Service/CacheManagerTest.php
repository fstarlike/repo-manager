<?php

namespace WPGitManager\Tests\Unit\Service;

use PHPUnit\Framework\TestCase;
use WPGitManager\Service\CacheManager;

class CacheManagerTest extends TestCase
{
    private CacheManager $cacheManager;

    protected function setUp(): void
    {
        $this->cacheManager = CacheManager::instance();
        $this->cacheManager->clear();
    }

    protected function tearDown(): void
    {
        $this->cacheManager->clear();
    }

    public function testSetAndGetCache()
    {
        $key  = 'test-key';
        $data = ['test' => 'data', 'number' => 123];

        $this->cacheManager->set($key, $data);
        $retrieved = $this->cacheManager->get($key);

        $this->assertEquals($data, $retrieved);
    }

    public function testGetNonExistentCache()
    {
        $retrieved = $this->cacheManager->get('non-existent-key', 'default');
        $this->assertEquals('default', $retrieved);
    }

    public function testDeleteCache()
    {
        $key  = 'test-delete-key';
        $data = 'test data';

        $this->cacheManager->set($key, $data);
        $this->assertEquals($data, $this->cacheManager->get($key));

        $this->cacheManager->delete($key);
        $this->assertNull($this->cacheManager->get($key));
    }

    public function testRememberCache()
    {
        $key      = 'test-remember-key';
        $callback = (fn () => 'callback result');

        $result1 = $this->cacheManager->remember($key, $callback);
        $result2 = $this->cacheManager->remember($key, $callback);

        $this->assertEquals('callback result', $result1);
        $this->assertEquals('callback result', $result2);
        $this->assertEquals($result1, $result2);
    }

    public function testCacheGitResult()
    {
        $repoPath = '/test/repo';
        $command  = 'status';
        $args     = ['--porcelain'];
        $callback = (fn () => 'git output');

        $result = $this->cacheManager->cacheGitResult($repoPath, $command, $args, $callback);
        $this->assertEquals('git output', $result);
    }

    public function testCacheRepositoryData()
    {
        $repoId   = 'test-repo-123';
        $dataType = 'branches';
        $callback = (fn () => ['main', 'develop', 'feature']);

        $result = $this->cacheManager->cacheRepositoryData($repoId, $dataType, $callback);
        $this->assertEquals(['main', 'develop', 'feature'], $result);
    }

    public function testInvalidateRepository()
    {
        $repoId = 'test-repo-456';

        // Cache some data
        $this->cacheManager->cacheRepositoryData($repoId, 'branches', fn () => ['main', 'develop']);
        $this->cacheManager->cacheRepositoryData($repoId, 'commits', fn () => ['commit1', 'commit2']);

        // Verify data is cached
        $this->assertNotNull($this->cacheManager->get(sprintf('repo_%s_branches', $repoId)));
        $this->assertNotNull($this->cacheManager->get(sprintf('repo_%s_commits', $repoId)));

        // Invalidate repository
        $this->cacheManager->invalidateRepository($repoId);

        // Verify data is cleared
        $this->assertNull($this->cacheManager->get(sprintf('repo_%s_branches', $repoId)));
        $this->assertNull($this->cacheManager->get(sprintf('repo_%s_commits', $repoId)));
    }

    public function testGetStats()
    {
        $stats = $this->cacheManager->getStats();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('hits', $stats);
        $this->assertArrayHasKey('misses', $stats);
        $this->assertArrayHasKey('sets', $stats);
        $this->assertArrayHasKey('deletes', $stats);
        $this->assertArrayHasKey('hit_rate', $stats);
        $this->assertArrayHasKey('entry_count', $stats);
        $this->assertArrayHasKey('total_size', $stats);
        $this->assertArrayHasKey('memory_entries', $stats);
    }

    public function testClearCache()
    {
        $this->cacheManager->set('key1', 'data1');
        $this->cacheManager->set('key2', 'data2');

        $this->assertNotNull($this->cacheManager->get('key1'));
        $this->assertNotNull($this->cacheManager->get('key2'));

        $this->cacheManager->clear();

        $this->assertNull($this->cacheManager->get('key1'));
        $this->assertNull($this->cacheManager->get('key2'));
    }

    public function testOptimizeCache()
    {
        // Add many cache entries
        for ($i = 0; $i < 10; $i++) {
            $this->cacheManager->set('key' . $i, 'data' . $i);
        }

        $stats = $this->cacheManager->getStats();
        $this->assertEquals(10, $stats['entry_count']);

        // Optimize to keep only 5 entries
        $removed = $this->cacheManager->optimize(5);

        $stats = $this->cacheManager->getStats();
        $this->assertEquals(5, $stats['entry_count']);
        $this->assertEquals(5, $removed);
    }

    public function testGetHealthStatus()
    {
        $health = $this->cacheManager->getHealthStatus();

        $this->assertIsArray($health);
        $this->assertArrayHasKey('status', $health);
        $this->assertArrayHasKey('stats', $health);
        $this->assertArrayHasKey('recommendations', $health);
        $this->assertContains($health['status'], ['good', 'fair', 'poor']);
    }

    public function testCacheWithTTL()
    {
        $key  = 'test-ttl-key';
        $data = 'test data';
        $ttl  = 1; // 1 second

        $this->cacheManager->set($key, $data, $ttl);
        $this->assertEquals($data, $this->cacheManager->get($key));

        // Wait for expiration
        sleep(2);

        // Should return null after TTL expires
        $this->assertNull($this->cacheManager->get($key));
    }
}
