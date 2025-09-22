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
        add_action('wp_ajax_git_manager_repo_stash', [$this, 'stash']);
        add_action('wp_ajax_git_manager_repo_stash_pop', [$this, 'stashPop']);
        add_action('wp_ajax_git_manager_repo_checkout', [$this, 'checkout']);
        add_action('wp_ajax_git_manager_fetch', [$this, 'fetch']);
        add_action('wp_ajax_git_manager_pull', [$this, 'pull']);
        add_action('wp_ajax_git_manager_get_branches', [$this, 'getBranches']);
        // Note: git_manager_log is handled by MultiRepoAjax for proper commit formatting
        add_action('wp_ajax_git_manager_branch', [$this, 'branch']);
        add_action('wp_ajax_git_manager_latest_commit', [$this, 'latestCommit']);
    }

    /**
     * Execute Git command
     */
    public function executeGitCommand(): void
    {
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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $result = $this->gitRunner->run($resolvedPath, $command, $args);

            $this->auditLogger->logGitCommand($command, $resolvedPath, $result['success'], $result['output'] ?? null);

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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $result = $this->gitRunner->run($resolvedPath, 'push', $this->buildPushArgs($options));

            $this->auditLogger->logGitCommand('push', $resolvedPath, $result['success'], $result['output'] ?? null);

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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $result = $this->gitRunner->run($resolvedPath, 'merge', $this->buildMergeArgs($branch, $options));

            $this->auditLogger->logGitCommand('merge', $resolvedPath, $result['success'], $result['output'] ?? null);

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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $args   = $annotated ? ['-a', $tagName, '-m', $message] : [$tagName];
            $result = $this->gitRunner->run($resolvedPath, 'tag', $args);

            $this->auditLogger->logGitCommand('tag', $resolvedPath, $result['success'], $result['output'] ?? null);

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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $result = $this->gitRunner->run($resolvedPath, 'log', $this->buildLogArgs($options));

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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $args   = $checkout ? ['-b', $branchName] : [$branchName];
            $result = $this->gitRunner->run($resolvedPath, 'branch', $args);

            $this->auditLogger->logGitCommand('branch', $resolvedPath, $result['success'], $result['output'] ?? null);

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
     * Stash changes
     */
    public function stash(): void
    {
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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $args = ['push'];
            if (!empty($message)) {
                $args[] = '-m';
                $args[] = $message;
            }

            if ($includeUntracked) {
                $args[] = '--include-untracked';
            }

            $result = $this->gitRunner->run($resolvedPath, 'stash', $args);

            $this->auditLogger->logGitCommand('stash', $resolvedPath, $result['success'], $result['output'] ?? null);

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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $result = $this->gitRunner->run($resolvedPath, 'stash', ['pop']);

            $this->auditLogger->logGitCommand('stash pop', $resolvedPath, $result['success'], $result['output'] ?? null);

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
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_repo_checkout')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId = $this->getRepositoryId();
            $branch = sanitize_text_field(wp_unslash($_POST['branch'] ?? ''));
            $create = !empty($_POST['create']);
            $force  = !empty($_POST['force']);
            $remote = !empty($_POST['remote']);

            if (empty($branch)) {
                throw new \Exception('Branch name is required');
            }

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);

            // Check if repository is clean before attempting checkout (unless force is used)
            if (!$force) {
                $statusResult = $this->gitRunner->run($resolvedPath, 'status', ['--porcelain']);
                if (!in_array(trim($statusResult['output'] ?? ''), ['', '0'], true)) {
                    throw new \Exception('Cannot checkout: Repository has uncommitted changes. Please commit or stash your changes first.');
                }
            }

            // Fetch first to ensure we have latest remote branches
            $this->gitRunner->run($resolvedPath, 'fetch', ['--all'], ['low_priority' => true]);

            // Handle remote branch checkout
            if ($remote) {
                // For remote branches, create a local tracking branch
                $args = ['-b', $branch, 'origin/' . $branch];
                $result = $this->gitRunner->run($resolvedPath, 'checkout', $args);

                if (!$result['success']) {
                    // If creating from remote fails, try creating a new local branch
                    $args = ['-b', $branch];
                    $result = $this->gitRunner->run($resolvedPath, 'checkout', $args);
                }
            } else {
                // Check if local branch exists
                $localCheck = $this->gitRunner->run($resolvedPath, 'show-ref', ['--heads', 'refs/heads/' . $branch]);

                if (!empty($localCheck['output'])) {
                    // Local branch exists, just checkout
                    $args = [];
                    if ($force) {
                        $args[] = '--force';
                    }
                    $args[] = $branch;
                    $result = $this->gitRunner->run($resolvedPath, 'checkout', $args);
                } else {
                    // Try to checkout remote branch
                    $args = ['-b', $branch, 'origin/' . $branch];
                    $result = $this->gitRunner->run($resolvedPath, 'checkout', $args);

                    // If that fails, try creating a new branch
                    if (!$result['success']) {
                        $args = ['-b', $branch];
                        $result = $this->gitRunner->run($resolvedPath, 'checkout', $args);
                    }
                }
            }

            // Verify that checkout was successful by checking current branch
            if ($result['success']) {
                $currentBranchResult = $this->gitRunner->run($resolvedPath, 'rev-parse', ['--abbrev-ref', 'HEAD']);
                $currentBranch = trim($currentBranchResult['output'] ?? '');

                if ($currentBranch !== $branch) {
                    throw new \Exception('Checkout failed: Could not switch to branch ' . $branch . '. Current branch is: ' . $currentBranch);
                }
            }

            $this->auditLogger->logGitCommand('checkout', $resolvedPath, $result['success'], $result['output'] ?? null);

            if ($result['success']) {
                // Invalidate caches so other pages (dashboard) see the new branch immediately
                delete_transient('git_manager_cache_repo_list');
                delete_transient('git_manager_cache_repo_status_' . $repoId);
                delete_transient('git_manager_cache_repo_details_' . $repoId);
                delete_transient('git_manager_cache_latest_commit_' . $repoId);

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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $result = $this->gitRunner->run($resolvedPath, 'fetch', $this->buildFetchArgs($options));

            $this->auditLogger->logGitCommand('fetch', $resolvedPath, $result['success'], $result['output'] ?? null);

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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $result = $this->gitRunner->run($resolvedPath, 'pull', $this->buildPullArgs($options));

            $this->auditLogger->logGitCommand('pull', $resolvedPath, $result['success'], $result['output'] ?? null);

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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);

            // First, fetch latest remote information (don't fail if this doesn't work)
            $fetchResult = $this->gitRunner->run($resolvedPath, 'fetch', ['--all', '--prune'], ['low_priority' => true]);
            if (!$fetchResult['success']) {
                // Log the fetch error but don't fail the entire operation
                error_log('Repo Manager: Failed to fetch remote branches: ' . ($fetchResult['output'] ?? ''));
            }

            // Get local branches with verbose output to include tracking info
            $localResult = $this->gitRunner->run($resolvedPath, 'branch', ['-vv']);
            if (!$localResult['success']) {
                throw new \Exception('Failed to get local branches: ' . ($localResult['output'] ?? ''));
            }

            // Get remote branches
            $remoteResult = $this->gitRunner->run($resolvedPath, 'branch', ['-r']);
            if (!$remoteResult['success']) {
                throw new \Exception('Failed to get remote branches: ' . ($remoteResult['output'] ?? ''));
            }

            // Get current branch
            $currentResult = $this->gitRunner->run($resolvedPath, 'rev-parse', ['--abbrev-ref', 'HEAD']);
            $currentBranch = $currentResult['success'] ? trim($currentResult['output']) : null;

            // Parse local branches with status information
            $localBranches = [];
            $branchStatuses = [];

            if (!empty($localResult['output'])) {
                foreach (explode("\n", trim($localResult['output'])) as $line) {
                    $line = trim($line);
                    if (!empty($line)) {
                        // Remove * marker for current branch
                        $isCurrent = strpos($line, '*') === 0;
                        $branchName = trim(str_replace('*', '', $line));

                        if (!empty($branchName)) {
                            // Extract ahead/behind information from verbose output
                            $ahead = 0;
                            $behind = 0;
                            $hasUpstream = false;

                            // Check if branch has upstream tracking
                            if (preg_match('/\[(.*?)\]/', $line, $matches)) {
                                $upstreamInfo = $matches[1];
                                $hasUpstream = true;

                                // Extract ahead/behind numbers with better error handling
                                if (preg_match('/ahead (\d+)/', $upstreamInfo, $aheadMatches)) {
                                    $ahead = max(0, (int) $aheadMatches[1]); // Ensure non-negative
                                }
                                if (preg_match('/behind (\d+)/', $upstreamInfo, $behindMatches)) {
                                    $behind = max(0, (int) $behindMatches[1]); // Ensure non-negative
                                }

                                // Handle special cases like "gone" status
                                if (strpos($upstreamInfo, 'gone') !== false) {
                                    $hasUpstream = false; // Reset upstream flag if branch is gone
                                }
                            }

                            $localBranches[] = $branchName;
                            $branchStatuses[$branchName] = [
                                'name' => $branchName,
                                'isCurrent' => $isCurrent,
                                'ahead' => $ahead,
                                'behind' => $behind,
                                'hasUpstream' => $hasUpstream,
                                'needsPush' => $ahead > 0,
                                'needsPull' => $behind > 0,
                                'isDiverged' => $ahead > 0 && $behind > 0,
                            ];
                        }
                    }
                }
            }

            // Parse remote branches
            $remoteBranches = [];
            if (!empty($remoteResult['output'])) {
                foreach (explode("\n", trim($remoteResult['output'])) as $line) {
                    $line = trim($line);
                    if (!empty($line) && strpos($line, '->') === false) {
                        // Remove origin/ prefix for cleaner display
                        $branchName = preg_replace('/^origin\//', '', $line);
                        if (!empty($branchName)) {
                            $remoteBranches[] = $branchName;

                            // If this remote branch doesn't have a local equivalent, add it to statuses
                            if (!isset($branchStatuses[$branchName])) {
                                $branchStatuses[$branchName] = [
                                    'name' => $branchName,
                                    'isCurrent' => false,
                                    'ahead' => 0,
                                    'behind' => 0,
                                    'hasUpstream' => false,
                                    'needsPush' => false,
                                    'needsPull' => false,
                                    'isDiverged' => false,
                                    'isRemoteOnly' => true,
                                ];
                            }
                        }
                    }
                }
            }

            // Combine and deduplicate branches
            $allBranches = array_values(array_unique(array_merge($localBranches, $remoteBranches)));

            wp_send_json_success([
                'branches' => $allBranches,
                'local_branches' => $localBranches,
                'remote_branches' => $remoteBranches,
                'current_branch' => $currentBranch,
                'active_branch' => $currentBranch, // For compatibility
                'branch_statuses' => $branchStatuses,
            ]);
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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $result = $this->gitRunner->run($resolvedPath, 'log', $this->buildLogArgs($options));

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

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);
            $args   = $this->buildBranchArgs($operation, $_POST);
            $result = $this->gitRunner->run($resolvedPath, 'branch', $args);

            $this->auditLogger->logGitCommand('branch', $resolvedPath, $result['success'], $result['output'] ?? null);

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

        // Check nonce with better error handling
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'git_manager_action')) {
            wp_send_json_error('Invalid nonce. Please refresh the page and try again.');
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
     * Get latest commit information
     */
    public function latestCommit(): void
    {
        $this->ensureCapabilities();

        if (!$this->rateLimiter->checkAjaxRateLimit('git_manager_latest_commit')) {
            wp_send_json_error('Rate limit exceeded');
        }

        try {
            $repoId = $this->getRepositoryId();

            $repository = $this->repositoryManager->get($repoId);
            if (!$repository instanceof Repository) {
                throw new \Exception('Repository not found');
            }

            $resolvedPath = $this->repositoryManager->resolvePath($repository->path);

            // Get latest commit info
            $result = $this->gitRunner->run($resolvedPath, 'log', ['-1', '--pretty=format:%H|%s|%an|%ad', '--date=relative']);

            if ($result['success'] && !empty($result['output'])) {
                $parts = explode('|', $result['output'], 4);
                if (count($parts) >= 4) {
                    wp_send_json_success([
                        'hash' => $parts[0],
                        'message' => $parts[1],
                        'author' => $parts[2],
                        'date' => $parts[3],
                        'short_hash' => substr($parts[0], 0, 7),
                    ]);
                } else {
                    wp_send_json_success([
                        'hash' => '',
                        'message' => 'No commits found',
                        'author' => '',
                        'date' => '',
                        'short_hash' => '',
                    ]);
                }
            } else {
                wp_send_json_error($result['output'] ?? 'Failed to get latest commit');
            }
        } catch (\Exception $exception) {
            $this->auditLogger->log('error', 'git_latest_commit_failed', [
                'error'   => $exception->getMessage(),
                'repo_id' => $repoId ?? null,
            ]);
            wp_send_json_error($exception->getMessage());
        }
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
                return [empty($data['force']) ? '-d' : '-D', sanitize_text_field($data['branch_name'] ?? '')];
            case 'list':
            default:
                return ['-a', '-v'];
        }
    }
}
