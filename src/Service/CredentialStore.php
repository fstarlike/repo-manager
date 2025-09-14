<?php

namespace WPGitManager\Service;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Secure credential store with proper encryption.
 * Uses WordPress salts and OpenSSL for secure credential storage.
 */
class CredentialStore
{
    private const OPTION_KEY = 'git_manager_repo_credentials';

    private const ENCRYPTION_METHOD = 'AES-256-CBC';

    private const KEY_LENGTH = 32;

    private const IV_LENGTH = 16;

    /**
     * Generate encryption key from WordPress salts
     */
    private static function getEncryptionKey(): string
    {
        $salt = AUTH_SALT . SECURE_AUTH_SALT . NONCE_SALT . LOGGED_IN_SALT;
        return hash('sha256', $salt, true);
    }

    /**
     * Encrypt sensitive data
     */
    private static function encrypt(string $data): string
    {
        if ('' === $data || '0' === $data) {
            return '';
        }

        $key       = self::getEncryptionKey();
        $iv        = random_bytes(self::IV_LENGTH);
        $encrypted = openssl_encrypt($data, self::ENCRYPTION_METHOD, $key, 0, $iv);

        if (false === $encrypted) {
            throw new \RuntimeException('Encryption failed');
        }

        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt sensitive data
     */
    private static function decrypt(string $encryptedData): string
    {
        if ('' === $encryptedData || '0' === $encryptedData) {
            return '';
        }

        $key  = self::getEncryptionKey();
        $data = base64_decode($encryptedData);

        if (false === $data || strlen($data) < self::IV_LENGTH) {
            throw new \RuntimeException('Invalid encrypted data');
        }

        $iv        = substr($data, 0, self::IV_LENGTH);
        $encrypted = substr($data, self::IV_LENGTH);

        $decrypted = openssl_decrypt($encrypted, self::ENCRYPTION_METHOD, $key, 0, $iv);

        if (false === $decrypted) {
            throw new \RuntimeException('Decryption failed');
        }

        return $decrypted;
    }

    public static function set(string $repoId, array $data): void
    {
        $all = get_option(self::OPTION_KEY, []);
        if (! is_array($all)) {
            $all = [];
        }

        // Encrypt sensitive fields
        $sensitiveFields = ['private_key', 'password', 'token'];
        foreach ($sensitiveFields as $field) {
            if (isset($data[$field]) && !empty($data[$field])) {
                try {
                    $data[$field] = self::encrypt($data[$field]);
                } catch (\RuntimeException $e) {
                    unset($data[$field]); // Remove field if encryption fails
                }
            }
        }

        $all[$repoId] = $data;
        update_option(self::OPTION_KEY, $all, false);
    }

    public static function get(string $repoId, bool $raw = false): ?array
    {
        $all = get_option(self::OPTION_KEY, []);
        if (! is_array($all) || ! isset($all[$repoId])) {
            return null;
        }

        $cred            = $all[$repoId];
        $sensitiveFields = ['private_key', 'password', 'token'];

        if (! $raw) {
            // Mask sensitive fields for display
            foreach ($sensitiveFields as $field) {
                if (isset($cred[$field])) {
                    $cred[$field] = '[hidden]';
                }
            }
        } else {
            // Decrypt sensitive fields for use
            foreach ($sensitiveFields as $field) {
                if (isset($cred[$field]) && !empty($cred[$field])) {
                    try {
                        $cred[$field] = self::decrypt($cred[$field]);
                    } catch (\RuntimeException $e) {
                        $cred[$field] = ''; // Clear field if decryption fails
                    }
                }
            }
        }

        return $cred;
    }

    /**
     * Validate encryption/decryption functionality
     */
    public static function validateEncryption(): bool
    {
        try {
            $testData  = 'test_credential_data_' . time();
            $encrypted = self::encrypt($testData);
            $decrypted = self::decrypt($encrypted);
            return $decrypted === $testData;
        } catch (\RuntimeException $runtimeException) {
            return false;
        }
    }

    /**
     * Clear all credentials (for security purposes)
     */
    public static function clearAll(): void
    {
        delete_option(self::OPTION_KEY);
    }

    /**
     * Get encryption status
     */
    public static function getEncryptionStatus(): array
    {
        return [
            'method'            => self::ENCRYPTION_METHOD,
            'key_length'        => self::KEY_LENGTH,
            'iv_length'         => self::IV_LENGTH,
            'openssl_available' => extension_loaded('openssl'),
            'validation_passed' => self::validateEncryption(),
        ];
    }
}
