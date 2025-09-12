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
 * Git operations controller
 * Handles Git-specific operations
 */
class GitController
{
    private RepositoryManager $repositoryManager;

    private SecureGitRunner $gitRunner;

    private AuditLogger $auditLogger;

    private RateLimiter $rateLimiter;

    public function __construct()
    {
        $this->repositoryManager = RepositoryManager::instance();
        $this->gitRunner         = new SecureGitRunner();
        $this->auditLogger       = AuditLogger::instance();
        $this->rateLimiter       = RateLimiter::instance();
    }

    public function register(): void
    {
        add_action('wp_ajax_git_manager_repo_git', [$this, 'executeGitCommand']);
        add_action('wp_ajax_git_manager_repo_push', [$this, 'push']);
        add_action('wp_ajax_git_manager_repo_merge', [$this, 'merge']);
        add_action('wp_ajax_git_manager_repo_tag', [$this, 'createTag']);
        add_action('wp_ajax_git_manager_repo_log', [$this, 'detailedLog']);
        add_action('wp_ajax_git_manager_detailed_log', [$this, 'detailedLog']);
        add_action('wp_ajax_git_manager_repo_create_branch', [$this, 'createBranch']);
        add_action('wp_ajax_git_manager_repo_delete_branch', [$this, 'deleteBranch']);
        add_action('wp_ajax_git_manager_repo_stash', [$this, 'stash']);
        add_action('wp_ajax_git_manager_repo_stash_pop', [$this, 'stashPop']);
        add_action('wp_ajax_git_manager_repo_checkout', [$this, 'checkout']);
        add_action('wp_ajax_git_manager_checkout', [$this, 'checkout']);
        add_action('wp_ajax_git_manager_fetch', [$this, 'fetch']);
        add_action('wp_ajax_git_manager_pull', [$this, 'pull']);
        add_action('wp_ajax_git_manager_get_branches', [$this, 'getBranches']);
        add_action('wp_ajax_git_manager_log', [$this, 'log']);
        add_action('wp_ajax_git_manager_branch', [$this, 'branch']);
        add_action('wp_ajax_git_manager_latest_commit', [$this, 'latestCommit']);
    }

    /**
     * Execute Git command
     */
    public function executeGitCommand(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_git')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId  = $this->getRepositoryId();
            $command = isset($_POST['command']) ? sanitize_text_field(wp_unslash($_POST['command'])) : '';

            $args = [];
            if (isset($_POST['args']) && is_array($_POST['args'])) {
                $args = array_map('sanitize_text_field', wp_unslash($_POST['args']));
            }

            if (empty($command)) {
                throw new \Exception('Git command is required');
            }

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $result = $this->gitRunner->run($repository->path, $command, $args);

            $this->auditLogger->logGitCommand($command, $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Command failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_command_failed', [
                'error'   => $exception->getMessage(),
                'command' => $command ?? null,
                'repo_id' => $repoId ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Push changes
     */
    public function push(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_push')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId  = $this->getRepositoryId();
            $options = [
                'force'          => !empty($_POST['force']),
                'forceWithLease' => !empty($_POST['force_with_lease']),
                'setUpstream'    => !empty($_POST['set_upstream']),
            ];

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $result = $this->gitRunner->run($repository->path, 'push', $this->buildPushArgs($options));

            $this->auditLogger->logGitCommand('push', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Push failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_push_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Merge branch
     */
    public function merge(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_merge')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId  = $this->getRepositoryId();
            $branch  = sanitize_text_field(wp_unslash($_POST['branch'] ?? ''));
            $options = [
                'noFF'   => !empty($_POST['no_ff']),
                'ffOnly' => !empty($_POST['ff_only']),
                'squash' => !empty($_POST['squash']),
            ];

            if (empty($branch)) {
                throw new \Exception('Branch name is required');
            }

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $result = $this->gitRunner->run($repository->path, 'merge', $this->buildMergeArgs($branch, $options));

            $this->auditLogger->logGitCommand('merge', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Merge failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_merge_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
                'branch'  => $branch ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Create tag
     */
    public function createTag(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_tag')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId    = $this->getRepositoryId();
            $tagName   = sanitize_text_field(wp_unslash($_POST['tag_name'] ?? ''));
            $message   = sanitize_text_field(wp_unslash($_POST['message'] ?? ''));
            $annotated = !empty($_POST['annotated']);

            if (empty($tagName)) {
                throw new \Exception('Tag name is required');
            }

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $args   = $annotated ? ['-a', $tagName, '-m', $message] : [$tagName];
            $result = $this->gitRunner->run($repository->path, 'tag', $args);

            $this->auditLogger->logGitCommand('tag', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Tag creation failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_tag_failed', [
                'error'    => $exception->getMessage(),
                'repo_id'  => $repoId ?? null,
                'tag_name' => $tagName ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Get detailed log
     */
    public function detailedLog(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_detailed_log')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId  = $this->getRepositoryId();
            $options = [
                'maxCount' => isset($_POST['max_count']) ? intval(wp_unslash($_POST['max_count'])) : 50,
                'since'    => sanitize_text_field(wp_unslash($_POST['since'] ?? '')),
                'until'    => sanitize_text_field(wp_unslash($_POST['until'] ?? '')),
                'author'   => sanitize_text_field(wp_unslash($_POST['author'] ?? '')),
                'grep'     => sanitize_text_field(wp_unslash($_POST['grep'] ?? '')),
            ];

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $result = $this->gitRunner->run($repository->path, 'log', $this->buildLogArgs($options));

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Log retrieval failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_log_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Create branch
     */
    public function createBranch(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_create_branch')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId     = $this->getRepositoryId();
            $branchName = sanitize_text_field(wp_unslash($_POST['branch_name'] ?? ''));
            $checkout   = !empty($_POST['checkout']);

            if (empty($branchName)) {
                throw new \Exception('Branch name is required');
            }

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $args   = $checkout ? ['-b', $branchName] : [$branchName];
            $result = $this->gitRunner->run($repository->path, 'branch', $args);

            $this->auditLogger->logGitCommand('branch', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Branch creation failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_branch_create_failed', [
                'error'       => $exception->getMessage(),
                'repo_id'     => $repoId ?? null,
                'branch_name' => $branchName ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Delete branch
     */
    public function deleteBranch(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_delete_branch')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId     = $this->getRepositoryId();
            $branchName = sanitize_text_field(wp_unslash($_POST['branch_name'] ?? ''));
            $force      = !empty($_POST['force']);

            if (empty($branchName)) {
                throw new \Exception('Branch name is required');
            }

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $args   = $force ? ['-D', $branchName] : ['-d', $branchName];
            $result = $this->gitRunner->run($repository->path, 'branch', $args);

            $this->auditLogger->logGitCommand('branch', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Branch deletion failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_branch_delete_failed', [
                'error'       => $exception->getMessage(),
                'repo_id'     => $repoId ?? null,
                'branch_name' => $branchName ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Stash changes
     */
    public function stash(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_stash')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId           = $this->getRepositoryId();
            $message          = sanitize_text_field(wp_unslash($_POST['message'] ?? ''));
            $includeUntracked = !empty($_POST['include_untracked']);

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $args = ['push'];
            if (!empty($message)) {
                $args[] = '-m';
                $args[] = $message;
            }

            if ($includeUntracked) {
                $args[] = '--include-untracked';
            }

            $result = $this->gitRunner->run($repository->path, 'stash', $args);

            $this->auditLogger->logGitCommand('stash', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Stash failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_stash_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Pop stash
     */
    public function stashPop(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_stash_pop')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId = $this->getRepositoryId();

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $result = $this->gitRunner->run($repository->path, 'stash', ['pop']);

            $this->auditLogger->logGitCommand('stash pop', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Stash pop failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_stash_pop_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Checkout branch
     */
    public function checkout(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_checkout')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId = $this->getRepositoryId();
            $branch = sanitize_text_field(wp_unslash($_POST['branch'] ?? ''));
            $create = !empty($_POST['create']);
            $force  = !empty($_POST['force']);

            if (empty($branch)) {
                throw new \Exception('Branch name is required');
            }

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $args = [];
            if ($create) {
                $args[] = '-b';
            }

            if ($force) {
                $args[] = '--force';
            }

            $args[] = $branch;

            $result = $this->gitRunner->run($repository->path, 'checkout', $args);

            $this->auditLogger->logGitCommand('checkout', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Checkout failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_checkout_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
                'branch'  => $branch ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Fetch changes
     */
    public function fetch(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_fetch')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId  = $this->getRepositoryId();
            $options = [
                'all'   => !empty($_POST['all']),
                'prune' => !empty($_POST['prune']),
                'tags'  => !empty($_POST['tags']),
            ];

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $result = $this->gitRunner->run($repository->path, 'fetch', $this->buildFetchArgs($options));

            $this->auditLogger->logGitCommand('fetch', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Fetch failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_fetch_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Pull changes
     */
    public function pull(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_pull')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId  = $this->getRepositoryId();
            $options = [
                'rebase' => !empty($_POST['rebase']),
                'ffOnly' => !empty($_POST['ff_only']),
                'noFF'   => !empty($_POST['no_ff']),
            ];

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $result = $this->gitRunner->run($repository->path, 'pull', $this->buildPullArgs($options));

            $this->auditLogger->logGitCommand('pull', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Pull failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_pull_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Get branches
     */
    public function getBranches(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_get_branches')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId = $this->getRepositoryId();

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $result = $this->gitRunner->run($repository->path, 'branch', ['-a', '-v']);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Branch listing failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_branches_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Get commit log
     */
    public function log(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_log')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId  = $this->getRepositoryId();
            $options = [
                'maxCount' => intval(wp_unslash($_POST['max_count'] ?? 10)),
                'since'    => sanitize_text_field(wp_unslash($_POST['since'] ?? '')),
                'until'    => sanitize_text_field(wp_unslash($_POST['until'] ?? '')),
            ];

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $result = $this->gitRunner->run($repository->path, 'log', $this->buildLogArgs($options));

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Log retrieval failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_log_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
    }

    /**
     * Branch operations
     */
    public function branch(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_branch')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId    = $this->getRepositoryId();
            $operation = sanitize_text_field(wp_unslash($_POST['operation'] ?? 'list'));

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $args   = $this->buildBranchArgs($operation, $_POST);
            $result = $this->gitRunner->run($repository->path, 'branch', $args);

            $this->auditLogger->logGitCommand('branch', $repository->path, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                wp_send_json_success($result);
            } else {
                wp_send_json_error($result['output'] ?? 'Branch operation failed');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_branch_failed', [
                'error'     => $exception->getMessage(),
                'repo_id'   => $repoId ?? null,
                'operation' => $operation ?? null,
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
     * Build push arguments
     */
    private function buildPushArgs(array $options): array
    {
        $args = [];

        if ($options['force']) {
            $args[] = '--force';
        } elseif ($options['forceWithLease']) {
            $args[] = '--force-with-lease';
        }

        if ($options['setUpstream']) {
            $args[] = '--set-upstream';
        }

        return $args;
    }

    /**
     * Build merge arguments
     */
    private function buildMergeArgs(string $branch, array $options): array
    {
        $args = [$branch];

        if ($options['noFF']) {
            $args[] = '--no-ff';
        } elseif ($options['ffOnly']) {
            $args[] = '--ff-only';
        }

        if ($options['squash']) {
            $args[] = '--squash';
        }

        return $args;
    }

    /**
     * Build log arguments
     */
    private function buildLogArgs(array $options): array
    {
        $args = ['--oneline'];

        if ($options['maxCount'] > 0) {
            $args[] = '--max-count';
            $args[] = (string) $options['maxCount'];
        }

        if (!empty($options['since'])) {
            $args[] = '--since';
            $args[] = $options['since'];
        }

        if (!empty($options['until'])) {
            $args[] = '--until';
            $args[] = $options['until'];
        }

        if (!empty($options['author'])) {
            $args[] = '--author';
            $args[] = $options['author'];
        }

        if (!empty($options['grep'])) {
            $args[] = '--grep';
            $args[] = $options['grep'];
        }

        return $args;
    }

    /**
     * Build fetch arguments
     */
    private function buildFetchArgs(array $options): array
    {
        $args = [];

        if ($options['all']) {
            $args[] = '--all';
        }

        if ($options['prune']) {
            $args[] = '--prune';
        }

        if ($options['tags']) {
            $args[] = '--tags';
        }

        return $args;
    }

    /**
     * Build pull arguments
     */
    private function buildPullArgs(array $options): array
    {
        $args = [];

        if ($options['rebase']) {
            $args[] = '--rebase';
        } elseif ($options['ffOnly']) {
            $args[] = '--ff-only';
        } elseif ($options['noFF']) {
            $args[] = '--no-ff';
        }

        return $args;
    }

    /**
     * Build branch arguments
     */
    private function buildBranchArgs(string $operation, array $data): array
    {
        switch ($operation) {
            case 'create':
                $args = [];
                if (!empty($data['checkout'])) {
                    $args[] = '-b';
                }

                $args[] = sanitize_text_field($data['branch_name'] ?? '');
                return $args;
            case 'delete':
                $args = [];
                $args[] = empty($data['force']) ? '-d' : '-D';

                $args[] = sanitize_text_field($data['branch_name'] ?? '');
                return $args;
            case 'list':
            default:
                return ['-a', '-v'];
        }
    }
}
