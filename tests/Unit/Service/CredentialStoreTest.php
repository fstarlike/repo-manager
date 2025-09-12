<?php

namespace WPGitManager\Tests\Unit\Service;

use PHPUnit\Framework\TestCase;
use WPGitManager\Service\CredentialStore;

class CredentialStoreTest extends TestCase
{
    protected function setUp(): void
    {
        // Clear any existing credentials
        CredentialStore::clearAll();
    }

    protected function tearDown(): void
    {
        // Clean up
        CredentialStore::clearAll();
    }

    public function testEncryptionValidation()
    {
        $this->assertTrue(CredentialStore::validateEncryption());
    }

    public function testSetAndGetCredentials()
    {
        $repoId      = 'test-repo-123';
        $credentials = [
            'username'    => 'testuser',
            'password'    => 'testpassword',
            'private_key' => 'test-private-key',
            'token'       => 'test-token',
        ];

        // Set credentials
        CredentialStore::set($repoId, $credentials);

        // Get credentials (raw)
        $retrieved = CredentialStore::get($repoId, true);

        $this->assertNotNull($retrieved);
        $this->assertEquals('testuser', $retrieved['username']);
        $this->assertEquals('testpassword', $retrieved['password']);
        $this->assertEquals('test-private-key', $retrieved['private_key']);
        $this->assertEquals('test-token', $retrieved['token']);
    }

    public function testMaskedCredentials()
    {
        $repoId      = 'test-repo-456';
        $credentials = [
            'username'    => 'testuser',
            'password'    => 'testpassword',
            'private_key' => 'test-private-key',
            'token'       => 'test-token',
        ];

        CredentialStore::set($repoId, $credentials);

        // Get credentials (masked)
        $retrieved = CredentialStore::get($repoId, false);

        $this->assertNotNull($retrieved);
        $this->assertEquals('testuser', $retrieved['username']);
        $this->assertEquals('[hidden]', $retrieved['password']);
        $this->assertEquals('[hidden]', $retrieved['private_key']);
        $this->assertEquals('[hidden]', $retrieved['token']);
    }

    public function testGetNonExistentCredentials()
    {
        $retrieved = CredentialStore::get('non-existent-repo');
        $this->assertNull($retrieved);
    }

    public function testEncryptionStatus()
    {
        $status = CredentialStore::getEncryptionStatus();

        $this->assertIsArray($status);
        $this->assertArrayHasKey('method', $status);
        $this->assertArrayHasKey('openssl_available', $status);
        $this->assertArrayHasKey('validation_passed', $status);
        $this->assertEquals('AES-256-CBC', $status['method']);
        $this->assertTrue($status['openssl_available']);
        $this->assertTrue($status['validation_passed']);
    }

    public function testClearAllCredentials()
    {
        $repoId      = 'test-repo-789';
        $credentials = ['username' => 'testuser'];

        CredentialStore::set($repoId, $credentials);
        $this->assertNotNull(CredentialStore::get($repoId));

        CredentialStore::clearAll();
        $this->assertNull(CredentialStore::get($repoId));
    }

    public function testEmptyCredentials()
    {
        $repoId      = 'test-repo-empty';
        $credentials = [
            'username'    => 'testuser',
            'password'    => '',
            'private_key' => null,
            'token'       => '   ', // whitespace only
        ];

        CredentialStore::set($repoId, $credentials);
        $retrieved = CredentialStore::get($repoId, true);

        $this->assertEquals('testuser', $retrieved['username']);
        $this->assertArrayNotHasKey('password', $retrieved);
        $this->assertArrayNotHasKey('private_key', $retrieved);
        $this->assertArrayNotHasKey('token', $retrieved);
    }
}
