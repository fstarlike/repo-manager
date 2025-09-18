<?php

namespace WPGitManager\Controller;

use WPGitManager\Model\Repository;
use WPGitManager\Service\AuditLogger;
use WPGitManager\Service\RateLimiter;
use WPGitManager\Service\RepositoryManager;
use WPGitManager\Service\SecureGitRunner;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Repository-specific AJAX controller
 * Handles repository CRUD operations
 */
class RepositoryController
{
    private RepositoryManager $repositoryManager;

    private AuditLogger $auditLogger;

    private RateLimiter $rateLimiter;

    public function __construct()
    {
        $this->repositoryManager = RepositoryManager::instance();
        $this->auditLogger       = AuditLogger::instance();
        $this->rateLimiter       = RateLimiter::instance();
    }

    public function register(): void
    {
        add_action('wp_ajax_git_manager_repo_list', [$this, 'list']);
        add_action('wp_ajax_git_manager_get_repos', [$this, 'list']);
        add_action('wp_ajax_git_manager_repo_add', [$this, 'add']);
        add_action('wp_ajax_git_manager_repo_update', [$this, 'update']);
        add_action('wp_ajax_git_manager_repo_delete', [$this, 'delete']);
        add_action('wp_ajax_git_manager_delete_repo', [$this, 'delete']);
        add_action('wp_ajax_git_manager_repo_clone', [$this, 'clone']);
        add_action('wp_ajax_git_manager_clone_repo', [$this, 'clone']);
        add_action('wp_ajax_git_manager_repo_details', [$this, 'getDetails']);
        add_action('wp_ajax_git_manager_get_repo_details', [$this, 'getDetails']);
        add_action('wp_ajax_git_manager_repo_set_active', [$this, 'setActive']);
        add_action('wp_ajax_git_manager_repo_add_existing', [$this, 'addExisting']);
        add_action('wp_ajax_git_manager_add_existing_repo', [$this, 'addExisting']);
        add_action('wp_ajax_git_manager_migrate_paths', [$this, 'migratePaths']);
    }

    /**
     * List all repositories
     */
    public function list(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_list')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repositories = $this->repositoryManager->all();
            $activeId     = $this->repositoryManager->getActiveId();

            $this->auditLogger->logRepositoryOperation('list', 'all');

            wp_send_json_success([
                'repositories' => $repositories,
                'active_id'    => $activeId,
            ]);
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'repository_list_failed', [
                'error' => $exception->getMessage(),
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Add new repository
     */
    public function add(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_add')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $data       = $this->validateRepositoryData($_POST);
            $repository = $this->repositoryManager->add($data);

            $this->auditLogger->logRepositoryOperation('add', $repository->id, [
                'name' => $repository->name,
                'path' => $repository->path,
            ]);

            wp_send_json_success([
                'repository' => $repository->toArray(),
                'message'    => 'Repository added successfully',
            ]);
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'repository_add_failed', [
                'error' => $exception->getMessage(),
                'data'  => $_POST,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Update repository
     */
    public function update(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_update')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $id   = $this->getRepositoryId();
            $data = $this->validateRepositoryData($_POST);

            $repository = $this->repositoryManager->update($id, $data);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $this->auditLogger->logRepositoryOperation('update', $id, [
                'name' => $repository->name,
                'path' => $repository->path,
            ]);

            wp_send_json_success([
                'repository' => $repository->toArray(),
                'message'    => 'Repository updated successfully',
            ]);
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'repository_update_failed', [
                'error' => $exception->getMessage(),
                'id'    => $id ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Delete repository
     */
    public function delete(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_delete')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $id         = $this->getRepositoryId();
            $repository = $this->repositoryManager->get($id);

            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $success = $this->repositoryManager->delete($id);
            if (!$success) {
                throw new \Exception('Failed to delete repository');
            }

            $this->auditLogger->logRepositoryOperation('delete', $id, [
                'name' => $repository->name,
                'path' => $repository->path,
            ]);

            wp_send_json_success([
                'message' => 'Repository deleted successfully',
            ]);
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'repository_delete_failed', [
                'error' => $exception->getMessage(),
                'id'    => $id ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Clone repository
     */
    public function clone(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_clone')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $url    = sanitize_url(wp_unslash($_POST['url'] ?? ''));
            $path   = sanitize_text_field(wp_unslash($_POST['path'] ?? ''));
            $name   = sanitize_text_field(wp_unslash($_POST['name'] ?? ''));
            $branch = sanitize_text_field(wp_unslash($_POST['branch'] ?? ''));

            if (empty($url) || empty($path)) {
                throw new \Exception('URL and path are required');
            }

            // Validate path
            if (!$this->repositoryManager->validatePath($path)) {
                throw new \Exception('Invalid repository path');
            }

            // Clone the repository
            $result = $this->cloneRepository($url, $path, $branch);

            if (!$result['success']) {
                throw new \Exception($result['output']);
            }

            // Add to repository manager
            $data = [
                'name'      => $name ?: basename($path),
                'path'      => $path,
                'remoteUrl' => $url,
                'authType'  => 'ssh',
            ];

            $repository = $this->repositoryManager->add($data);

            $this->auditLogger->logRepositoryOperation('clone', $repository->id, [
                'url'    => $url,
                'path'   => $path,
                'branch' => $branch,
            ]);

            wp_send_json_success([
                'repository' => $repository->toArray(),
                'message'    => 'Repository cloned successfully',
            ]);
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'repository_clone_failed', [
                'error' => $exception->getMessage(),
                'url'   => $url ?? null,
                'path'  => $path ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Get repository details
     */
    public function getDetails(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_get_repo_details')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $id         = $this->getRepositoryId();
            $repository = $this->repositoryManager->get($id);

            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            // Get additional details
            $details = $this->getRepositoryDetails($repository);

            wp_send_json_success([
                'repository' => $repository->toArray(),
                'details'    => $details,
            ]);
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'repository_details_failed', [
                'error' => $exception->getMessage(),
                'id'    => $id ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Set active repository
     */
    public function setActive(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_set_active')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $id      = $this->getRepositoryId();
            $success = $this->repositoryManager->setActive($id);

            if (!$success) {
                throw new \Exception('Repository not found');
            }

            $this->auditLogger->logRepositoryOperation('set_active', $id);

            wp_send_json_success([
                'message' => 'Active repository set successfully',
            ]);
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'repository_set_active_failed', [
                'error' => $exception->getMessage(),
                'id'    => $id ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Add existing repository
     */
    public function addExisting(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_add_existing')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $path = sanitize_text_field(wp_unslash($_POST['path'] ?? ''));
            $name = sanitize_text_field(wp_unslash($_POST['name'] ?? ''));

            if (empty($path)) {
                throw new \Exception('Path is required');
            }

            // Validate path
            if (!$this->repositoryManager->validatePath($path)) {
                throw new \Exception('Invalid repository path');
            }

            // Check if it's a valid Git repository (supports .git dir or file)
            if (! \WPGitManager\Service\SecureGitRunner::isGitRepositoryPath($path)) {
                throw new \Exception('Not a valid Git repository');
            }

            // Add to repository manager
            $data = [
                'name'     => $name ?: basename($path),
                'path'     => $path,
                'authType' => 'ssh',
            ];

            $repository = $this->repositoryManager->add($data);

            $this->auditLogger->logRepositoryOperation('add_existing', $repository->id, [
                'name' => $repository->name,
                'path' => $repository->path,
            ]);

            wp_send_json_success([
                'repository' => $repository->toArray(),
                'message'    => 'Repository added successfully',
            ]);
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'repository_add_existing_failed', [
                'error' => $exception->getMessage(),
                'path'  => $path ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Ensure user is allowed to perform actions
     */
    private function ensureCapabilities(): void
    {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Access denied');
        }
    }

    /**
     * Get repository ID from request
     */
    private function getRepositoryId(): string
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $id = sanitize_text_field(wp_unslash($_POST['id'] ?? $_POST['repo_id'] ?? ''));

        if (empty($id)) {
            throw new \Exception('Repository ID is required');
        }

        return $id;
    }

    /**
     * Validate repository data
     */
    private function validateRepositoryData(array $data): array
    {
        $validated = [];

        if (isset($data['name'])) {
            $validated['name'] = sanitize_text_field(wp_unslash($data['name']));
            if (empty($validated['name'])) {
                throw new \Exception('Repository name is required');
            }
        }

        if (isset($data['path'])) {
            $rawPath = sanitize_text_field(wp_unslash($data['path']));
            if (empty($rawPath)) {
                throw new \Exception('Repository path is required');
            }

            // Resolve the path to an absolute path before validation and saving.
            $validated['path'] = $this->repositoryManager->resolvePath($rawPath);

            if (!$this->repositoryManager->validatePath($validated['path'])) {
                throw new \Exception('Invalid repository path');
            }
        }

        if (isset($data['remoteUrl'])) {
            $validated['remoteUrl'] = sanitize_url(wp_unslash($data['remoteUrl']));
        }

        if (isset($data['authType'])) {
            $validated['authType'] = sanitize_text_field(wp_unslash($data['authType']));
        }

        return $validated;
    }

    /**
     * Clone repository using Git command
     */
    private function cloneRepository(string $url, string $path, string $branch = ''): array
    {
        $clone = SecureGitRunner::cloneRepository($url, $path);
        if ('' !== $branch && '0' !== $branch && ($clone['success'] ?? false)) {
            $checkout = SecureGitRunner::runInDirectory($path, 'checkout ' . escapeshellarg($branch));
            if (!$checkout['success']) {
                return [
                    'success' => false,
                    'output'  => ($clone['output'] ?? '') . "\n" . ($checkout['output'] ?? 'Checkout failed'),
                ];
            }
        }

        return [
            'success' => (bool) ($clone['success'] ?? false),
            'output'  => $clone['output'] ?? '',
        ];
    }

    /**
     * Get repository details
     */
    private function getRepositoryDetails($repository): array
    {
        $details = [
            'status' => 'unknown',
            'branch' => 'unknown',
            'remote' => 'unknown',
        ];

        try {
            // Get Git status
            $statusRes = SecureGitRunner::runInDirectory($repository->path, 'status --porcelain');
            if (isset($statusRes['output'])) {
                $details['status'] = ('' === trim((string) $statusRes['output'])) ? 'clean' : 'dirty';
            }

            // Get current branch
            $branchRes = SecureGitRunner::runInDirectory($repository->path, 'branch --show-current');
            if (isset($branchRes['output'])) {
                $details['branch'] = trim((string) $branchRes['output']) ?: 'unknown';
            }

            // Get remote URL
            $remoteRes = SecureGitRunner::runInDirectory($repository->path, 'remote get-url origin');
            if (isset($remoteRes['output'])) {
                $details['remote'] = trim((string) $remoteRes['output']) ?: 'unknown';
            }

        } catch (\Exception $exception) {
            // Ignore errors in getting details
        }

        return $details;
    }

    /**
     * Migrate existing absolute paths to relative paths
     */
    public function migratePaths(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_migrate_paths')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $migrated = $this->repositoryManager->migrateAbsolutePathsToRelative();

            $this->auditLogger->log('info', 'paths_migrated', [
                'migrated_count' => $migrated,
            ]);

            wp_send_json_success([
                'message' => sprintf('Successfully migrated %d repository paths to relative paths', $migrated),
                'migrated_count' => $migrated,
            ]);
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'paths_migration_failed', [
                'error' => $exception->getMessage(),
            ]);
            wp_send_json_error('Failed to migrate paths: ' . $exception->getMessage());
        }
    }
}
