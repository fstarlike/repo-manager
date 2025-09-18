<?php

namespace WPGitManager\Controller;

use WPGitManager\Admin\GitManager;
use WPGitManager\Model\Repository;
use WPGitManager\Service\AuditLogger;
use WPGitManager\Service\CredentialStore;
use WPGitManager\Service\GitCommandRunner;
use WPGitManager\Service\RateLimiter;
use WPGitManager\Service\RepositoryManager;
use WPGitManager\Service\SecureGitRunner;
use WPGitManager\Service\SystemStatus;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * AJAX endpoints for multi-repository management
 */
class MultiRepoAjax
{
    private RateLimiter $rateLimiter;
    private AuditLogger $auditLogger;
    private CredentialStore $credentialStore;
    private SystemStatus $systemStatus;
    private RepositoryManager $repositoryManager;

    public function __construct(RateLimiter $rateLimiter, AuditLogger $auditLogger, CredentialStore $credentialStore, SystemStatus $systemStatus)
    {
        $this->rateLimiter       = $rateLimiter;
        $this->auditLogger       = $auditLogger;
        $this->credentialStore   = $credentialStore;
        $this->systemStatus      = $systemStatus;
        $this->repositoryManager = RepositoryManager::instance();
        add_action('wp_ajax_git_manager_repo_list', [$this, 'list']);
        add_action('wp_ajax_git_manager_add_repository', [$this, 'add']);
        add_action('wp_ajax_git_manager_repo_update', [$this, 'update']);
        add_action('wp_ajax_git_manager_repo_delete', [$this, 'delete']);
        add_action('wp_ajax_git_manager_repo_clone', [$this, 'clone']);
        add_action('wp_ajax_git_manager_repo_git', [$this, 'gitOp']);
        add_action('wp_ajax_git_manager_repo_dirs', [$this, 'listDirectories']);
        add_action('wp_ajax_git_manager_dir_create', [$this, 'createDirectory']);
        add_action('wp_ajax_git_manager_dir_delete', [$this, 'deleteDirectory']);
        add_action('wp_ajax_git_manager_dir_rename', [$this, 'renameDirectory']);
        add_action('wp_ajax_git_manager_repo_checkout', [$this, 'checkout']);
        add_action('wp_ajax_git_manager_repo_push', [$this, 'push']);
        add_action('wp_ajax_git_manager_repo_merge', [$this, 'merge']);
        add_action('wp_ajax_git_manager_repo_tag', [$this, 'createTag']);
        add_action('wp_ajax_git_manager_repo_log', [$this, 'detailedLog']);
        add_action('wp_ajax_git_manager_repo_set_active', [$this, 'setActive']);
        add_action('wp_ajax_git_manager_add_existing_repo', [$this, 'addExisting']);
        add_action('wp_ajax_git_manager_get_repo_details', [$this, 'getDetails']);
        add_action('wp_ajax_git_manager_repo_status', [$this, 'getStatus']);
        add_action('wp_ajax_git_manager_repo_create_branch', [$this, 'createBranch']);
        add_action('wp_ajax_git_manager_repo_delete_branch', [$this, 'deleteBranch']);
        add_action('wp_ajax_git_manager_repo_stash', [$this, 'stash']);
        add_action('wp_ajax_git_manager_repo_stash_pop', [$this, 'stashPop']);
        add_action('wp_ajax_git_manager_repo_troubleshoot', [$this, 'troubleshootRepo']);
        add_action('wp_ajax_git_manager_latest_commit', [$this, 'latestCommit']);
        add_action('wp_ajax_git_manager_fetch', [$this, 'fetch']);
        add_action('wp_ajax_git_manager_pull', [$this, 'pull']);
        add_action('wp_ajax_git_manager_get_branches', [$this, 'ajax_get_branches']);
        add_action('wp_ajax_git_manager_log', [$this, 'log']);
        add_action('wp_ajax_git_manager_branch', [$this, 'branch']);
        add_action('wp_ajax_git_manager_check_git_changes', [$this, 'checkGitChanges']);
        add_action('wp_ajax_git_manager_fix_permission', [$this, 'fixPermission']);
        add_action('wp_ajax_git_manager_fix_ssh', [$this, 'fixSsh']);
        add_action('wp_ajax_git_manager_save_roles', [$this, 'saveRoles']);
        add_action('wp_ajax_git_manager_safe_directory', [$this, 'safeDirectory']);
        add_action('wp_ajax_git_manager_troubleshoot_step', [$this, 'troubleshootStep']);
        add_action('wp_ajax_git_manager_troubleshoot', [$this, 'troubleshoot']);
        add_action('wp_ajax_git_manager_repo_reclone', [$this, 'reClone']);
        add_action('wp_ajax_git_manager_bulk_repo_status', [$this, 'getBulkRepoStatus']);
    }

    private function ensureAllowed(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error('Access denied');
        }

        check_ajax_referer('git_manager_action', 'nonce');
    }

    private function getRepositoryId(): string
    {
        // Nonce is verified in ensureAllowed() or manually in the public AJAX handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $id = sanitize_text_field(wp_unslash($_POST['id'] ?? $_POST['repo_id'] ?? ''));

        return trim($id);
    }

    /**
     * Determine repository type based on its path
     */
    private function determineRepositoryType(string $path): string
    {
        $realPath = realpath($path);
        if (false === $realPath) {
            return 'other';
        }

        // Normalize paths to use forward slashes for consistent comparison
        $realPath     = str_replace('\\', '/', $realPath);
        $wpPluginDir  = str_replace('\\', '/', WP_PLUGIN_DIR);
        $wpContentDir = str_replace('\\', '/', WP_CONTENT_DIR);

        // Check if it's a plugin
        if (0 === strpos($realPath, (string) $wpPluginDir)) {
            return 'plugin';
        }

        // Check if it's a theme
        $themesDir      = get_template_directory();
        $parentThemeDir = dirname($themesDir);
        str_replace('\\', '/', $themesDir);
        $parentThemeDir = str_replace('\\', '/', $parentThemeDir);

        if (0 === strpos($realPath, $parentThemeDir)) {
            return 'theme';
        }

        // Check if it's in wp-content/themes directory
        $wpContentThemesDir = $wpContentDir . '/themes';

        if (0 === strpos($realPath, $wpContentThemesDir)) {
            return 'theme';
        }

        return 'other';
    }

    public function list(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error('Access denied');
        }

        $repos = $this->repositoryManager->all();
        $data  = array_map(fn ($repo) => $repo->toArray(), $repos);

        wp_send_json_success($data);
    }

    public function getDetails(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id = $this->getRepositoryId();

        if ('' === $id || '0' === $id) {
            wp_send_json_error('Repository ID is required');
        }

        $repo = $this->repositoryManager->get($id);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Cache-first
        $cacheKey = 'git_manager_cache_repo_details_' . $id;
        $cached   = get_transient($cacheKey);
        if (false !== $cached) {
            wp_send_json_success($cached);
        }

        // Get current branch
        $currentBranch      = GitCommandRunner::run($resolvedPath, 'rev-parse --abbrev-ref HEAD');
        $repo->activeBranch = trim($currentBranch['output'] ?? 'Unknown');

        // If branch detection failed, try alternative method
        if ('' === $repo->activeBranch || '0' === $repo->activeBranch || 'Unknown' === $repo->activeBranch) {
            $statusResult = GitCommandRunner::run($resolvedPath, 'status --porcelain --branch');
            if ($statusResult['success']) {
                $lines = explode("\n", trim($statusResult['output'] ?? ''));
                foreach ($lines as $line) {
                    if (0 === strpos($line, '##') && preg_match('/## ([^\.]+)/', $line, $matches)) {
                        $repo->activeBranch = $matches[1];
                        break;
                    }
                }
            }
        }

        // If still no branch, try to get it from HEAD
        if ('' === $repo->activeBranch || '0' === $repo->activeBranch || 'Unknown' === $repo->activeBranch) {
            $headResult         = GitCommandRunner::run($resolvedPath, 'symbolic-ref --short HEAD');
            $repo->activeBranch = trim($headResult['output'] ?? 'main');
        }

        // Final fallback for branch name
        if ('' === $repo->activeBranch || '0' === $repo->activeBranch) {
            $repo->activeBranch = 'main';
        }

        // Ensure branch name is not empty
        if ('' === $repo->activeBranch || '0' === $repo->activeBranch) {
            $repo->activeBranch = 'Unknown';
        }

        // Get branch status (ahead/behind)
        $branchStatus = GitCommandRunner::run($resolvedPath, 'status --porcelain --branch');
        $ahead        = 0;
        $behind       = 0;
        if ($branchStatus['success']) {
            $lines = explode("\n", trim($branchStatus['output'] ?? ''));
            foreach ($lines as $line) {
                if (0 === strpos($line, '##')) {
                    if (preg_match('/ahead (\d+)/', $line, $matches)) {
                        $ahead = (int) $matches[1];
                    }

                    if (preg_match('/behind (\d+)/', $line, $matches)) {
                        $behind = (int) $matches[1];
                    }

                    break;
                }
            }
        }

        // Get repository status
        $status     = GitCommandRunner::run($resolvedPath, 'status --porcelain');
        $hasChanges = !in_array(trim($status['output'] ?? ''), ['', '0'], true);

        // Get remote info
        $remote    = GitCommandRunner::run($resolvedPath, 'remote get-url origin');
        $remoteUrl = trim($remote['output'] ?? '');

        // If no remote URL found, try to get it from config
        if ('' === $remoteUrl || '0' === $remoteUrl) {
            $configResult = GitCommandRunner::run($resolvedPath, 'config --get remote.origin.url');
            $remoteUrl    = trim($configResult['output'] ?? '');
        }

        // If still no remote URL, set default message
        if ('' === $remoteUrl || '0' === $remoteUrl) {
            $remoteUrl = 'No remote configured';
        }

        // Check if repository directory exists with improved path resolution
        $resolvedPath = $this->resolveRepositoryPath($repo->path);
        $directoryExists    = is_dir($resolvedPath);
        $gitDirectoryExists = is_dir($resolvedPath . '/.git');

        // If resolved path doesn't exist, try the original path as fallback
        if (!$directoryExists && $repo->path !== $resolvedPath) {
            $directoryExists = is_dir($repo->path);
            if ($directoryExists) {
                $resolvedPath = $repo->path;
                $gitDirectoryExists = is_dir($resolvedPath . '/.git');
            }
        }

        // If directory doesn't exist, return basic info for missing repositories
        if (! $directoryExists) {
            $details = [
                'id'           => $repo->id,
                'name'         => $repo->name,
                'path'         => $repo->path,
                'remoteUrl'    => $repo->remoteUrl,
                'activeBranch' => 'Folder Missing',
                'hasChanges'   => false,
                'ahead'        => 0,
                'behind'       => 0,
                'authType'     => $repo->authType,
                'meta'         => $repo->meta,
                'folderExists' => false,
                'isValidGit'   => false,
            ];
            wp_send_json_success($details);

            return;
        }

        // Check if .git directory exists
        if (! $gitDirectoryExists) {
            $details = [
                'id'           => $repo->id,
                'name'         => $repo->name,
                'path'         => $repo->path,
                'remoteUrl'    => $repo->remoteUrl,
                'activeBranch' => 'Not a Git repository',
                'hasChanges'   => false,
                'ahead'        => 0,
                'behind'       => 0,
                'authType'     => $repo->authType,
                'meta'         => $repo->meta,
                'folderExists' => true,
                'isValidGit'   => false,
            ];
            wp_send_json_success($details);

            return;
        }

        // Validate that this is actually a git repository
        $gitCheck = GitCommandRunner::run($resolvedPath, 'rev-parse --git-dir');
        if (! $gitCheck['success']) {
            $details = [
                'id'           => $repo->id,
                'name'         => $repo->name,
                'path'         => $repo->path,
                'remoteUrl'    => $repo->remoteUrl,
                'activeBranch' => 'Invalid Git repository',
                'hasChanges'   => false,
                'ahead'        => 0,
                'behind'       => 0,
                'authType'     => $repo->authType,
                'meta'         => $repo->meta,
                'folderExists' => true,
                'isValidGit'   => false,
            ];
            wp_send_json_success($details);

            return;
        }

        $details = [
            'id'           => $repo->id,
            'name'         => $repo->name,
            'path'         => realpath($repo->path) ?: stripslashes_deep($repo->path),
            'remoteUrl'    => $remoteUrl ?: $repo->remoteUrl,
            'activeBranch' => $repo->activeBranch,
            'hasChanges'   => $hasChanges,
            'ahead'        => $ahead,
            'behind'       => $behind,
            'authType'     => $repo->authType,
            'meta'         => $repo->meta,
            'folderExists' => true,
            'isValidGit'   => true,
        ];

        // Cache details for fast navigation
        set_transient($cacheKey, $details, 20);
        // Also refresh list cache lazily by deleting (will be rebuilt on next request)
        delete_transient('git_manager_cache_repo_list');
        wp_send_json_success($details);
    }

    public function getStatus(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id   = $this->getRepositoryId();
        $repo = $this->repositoryManager->get($id);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Cache-first
        $cacheKey = 'git_manager_cache_repo_status_' . $id;
        $cached   = get_transient($cacheKey);
        if (false !== $cached) {
            wp_send_json_success($cached);
        }

        // Get detailed status
        $status = GitCommandRunner::run($repo->path, 'status --porcelain --branch');
        $lines  = explode("\n", trim($status['output'] ?? ''));

        $statusInfo = [
            'hasChanges'     => false,
            'ahead'          => 0,
            'behind'         => 0,
            'currentBranch'  => 'Unknown',
            'modifiedFiles'  => [],
            'stagedFiles'    => [],
            'untrackedFiles' => [],
        ];

        foreach ($lines as $line) {
            if (0 === strpos($line, '##')) {
                // Branch info
                if (preg_match('/## ([^\.]+)(?:\.\.\.([^ ]+))?/', $line, $matches)) {
                    $statusInfo['currentBranch'] = $matches[1];
                    if (isset($matches[2])) {
                        if (preg_match('/ahead (\d+)/', $line, $ahead)) {
                            $statusInfo['ahead'] = (int) $ahead[1];
                        }

                        if (preg_match('/behind (\d+)/', $line, $behind)) {
                            $statusInfo['behind'] = (int) $behind[1];
                        }
                    }
                }
            } else {
                // File status
                if ('' === $line) {
                    continue;
                }

                $statusInfo['hasChanges'] = true;
                $status                   = substr($line, 0, 2);
                $file                     = substr($line, 3);

                if (' ' !== $status[0] && '?' !== $status[0]) {
                    $statusInfo['stagedFiles'][] = $file;
                }

                if (' ' !== $status[1] && '?' !== $status[1]) {
                    $statusInfo['modifiedFiles'][] = $file;
                }

                if ('??' === $status) {
                    $statusInfo['untrackedFiles'][] = $file;
                }
            }
        }

        // Add repository ID to the response
        $statusInfo['repoId'] = $id;
        set_transient($cacheKey, $statusInfo, 15);
        wp_send_json_success($statusInfo);
    }

    public function add(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');

        $data = [
            'name'      => sanitize_text_field(wp_unslash($_POST['name'] ?? '')),
            'path'      => sanitize_text_field(wp_unslash($_POST['path'] ?? '')),
            'remoteUrl' => sanitize_text_field(wp_unslash($_POST['remoteUrl'] ?? '')),
            'authType'  => sanitize_text_field(wp_unslash($_POST['authType'] ?? 'ssh')),
        ];
        if (! $data['path']) {
            wp_send_json_error('Path is required');
        }

        // Construct absolute path if relative path is provided
        $absolutePath = $data['path'];

        // Check if path is relative to WordPress root (starts with /wp-content, /wp-admin, etc.)
        $wpRelativePaths = ['/wp-content', '/wp-admin', '/wp-includes', '/wp-json'];
        $isWpRelative    = false;
        foreach ($wpRelativePaths as $wpPath) {
            if (0 === strpos($data['path'], $wpPath)) {
                $isWpRelative = true;
                break;
            }
        }

        if (! path_is_absolute($data['path']) || $isWpRelative) {
            $absolutePath = ABSPATH . ltrim($data['path'], '/');

        }

        if (! RepositoryManager::instance()->validatePath($absolutePath)) {
            wp_send_json_error('Invalid path');
        }

        // Check if this is an existing repository
        $isExistingRepo = isset($_POST['existing_repo']) && '1' === $_POST['existing_repo'];

        // For new repositories, ensure the parent directory exists
        if (! $isExistingRepo) {
            $parentDir = dirname($absolutePath);
            if (!is_dir($parentDir) && ! wp_mkdir_p($parentDir)) {
                wp_send_json_error('Failed to create parent directory: ' . $parentDir);
            }
        }

        if ($isExistingRepo) {
            // For existing repositories, validate that it's actually a Git repository
            if (! \WPGitManager\Service\SecureGitRunner::isGitRepositoryPath($absolutePath)) {
                wp_send_json_error('Selected path is not a Git repository');
            }

            $data['path'] = realpath($absolutePath);
            // If name not provided for existing repo, infer from path
            if (empty($data['name'])) {
                $data['name'] = basename($data['path']);
            }
        } else {
            // For new repositories, we need to clone
            $remoteUrl = $data['remoteUrl'];
            if (! $remoteUrl) {
                wp_send_json_error('Repository URL is required for new repositories');
            }

            // Convert SSH URL to HTTPS if HTTPS authentication is provided or if SSH key is missing
            $authType   = sanitize_text_field(wp_unslash($_POST['authType'] ?? 'ssh'));
            $privateKey = empty($_POST['private_key']) ? '' : sanitize_textarea_field(wp_unslash($_POST['private_key']));

            if (0 === strpos($remoteUrl, 'git@') && ('https' === $authType || 'ssh' === $authType && empty($privateKey))) {
                // Convert git@github.com:user/repo.git to https://github.com/user/repo.git
                $remoteUrl = preg_replace('/^git@([^:]+):([^\/]+)\/([^\/]+?)(?:\.git)?$/', 'https://$1/$2/$3.git', $remoteUrl);
                // If we're converting to HTTPS but authType is still SSH, switch to HTTPS
                if ('ssh' === $authType && empty($privateKey)) {
                    $authType = 'https';
                }
            }

            // Extract repository name from URL if not provided
            if (! $data['name']) {
                $urlParts     = explode('/', $remoteUrl);
                $data['name'] = basename($urlParts[count($urlParts) - 1], '.git');
            }

            // Add repository name to the target path
            $absolutePath = rtrim($absolutePath, '/\\') . DIRECTORY_SEPARATOR . $data['name'];

            // Pre-flight check: ensure destination does not exist or is an empty directory
            if (is_dir($absolutePath) && count(array_diff(scandir($absolutePath), ['.', '..'])) > 0) {
                wp_send_json_error('Destination path already exists and is not an empty directory. Please choose a different location or clear the target folder.');
            }

            // Validate the final target path
            if (! RepositoryManager::instance()->validatePath($absolutePath)) {
                wp_send_json_error('Invalid target path');
            }

            // Clone the repository
            $authType   = sanitize_text_field(wp_unslash($_POST['authType'] ?? 'ssh'));
            $username   = sanitize_text_field(wp_unslash($_POST['username'] ?? ''));
            $token      = sanitize_text_field(wp_unslash($_POST['token'] ?? ''));
            $privateKey = empty($_POST['private_key']) ? '' : sanitize_textarea_field(wp_unslash($_POST['private_key']));

            // Prepare environment for Git
            $home               = getenv('HOME') ?: (getenv('USERPROFILE') ?: sys_get_temp_dir());
            $homeClean          = str_replace('"', '', $home);
            $env                = [];
            $remoteUrlFormatted = $remoteUrl;

            if ('https' === $authType && $username && $token) {
                $remoteUrlFormatted = preg_replace('#^https://#', 'https://' . rawurlencode($username) . ':' . rawurlencode($token) . '@', $remoteUrl);
            }

            if ('WIN' === strtoupper(substr(PHP_OS, 0, 3))) {
                $envStr = '';
                foreach ($env as $key => $value) {
                    $envStr .= sprintf('set "%s=%s" && ', $key, $value);
                }

                $cmd = $envStr . 'set "HOME=' . $homeClean . '" && git clone ' . escapeshellarg($remoteUrlFormatted) . ' ' . escapeshellarg($absolutePath) . ' 2>&1';
            } else {
                $envStr = '';
                foreach ($env as $key => $value) {
                    $envStr .= $key . '=' . escapeshellarg($value) . ' ';
                }

                $cmd = $envStr . 'HOME=' . escapeshellarg($home) . ' git clone ' . escapeshellarg($remoteUrlFormatted) . ' ' . escapeshellarg($absolutePath) . ' 2>&1';
            }

            // If SSH with private key is provided, create a temporary wrapper
            if ('ssh' === $authType && $privateKey) {
                $tmpDir = wp_upload_dir(null, false)['basedir'] . '/repo-manager-keys';
                if (! is_dir($tmpDir)) {
                    @wp_mkdir_p($tmpDir);
                }

                $keyPath = $tmpDir . '/key_' . md5($privateKey) . '.pem';
                if (! file_exists($keyPath)) {
                    file_put_contents($keyPath, $privateKey);
                    // Use WP_Filesystem instead of chmod
                    global $wp_filesystem;
                    if (empty($wp_filesystem)) {
                        require_once(ABSPATH . '/wp-admin/includes/file.php');
                        WP_Filesystem();
                    }

                    if ($wp_filesystem) {
                        $wp_filesystem->chmod($keyPath, 0600);
                    }
                }

                $isWin   = 'WIN' === strtoupper(substr(PHP_OS, 0, 3));
                $wrapper = $tmpDir . '/ssh_wrapper_' . md5($keyPath) . ($isWin ? '.bat' : '.sh');
                if ($isWin) {
                    if (! file_exists($wrapper)) {
                        file_put_contents($wrapper, "@echo off\nssh -i \"{$keyPath}\" -o StrictHostKeyChecking=no %*\n");
                    }

                    $cmd = 'set "GIT_SSH=' . $wrapper . '" && ' . $cmd;
                } else {
                    if (! file_exists($wrapper)) {
                        file_put_contents($wrapper, "#!/bin/sh\nexec ssh -i '{$keyPath}' -o StrictHostKeyChecking=no \"$@\"\n");
                        // Use WP_Filesystem instead of chmod
                        global $wp_filesystem;
                        if (empty($wp_filesystem)) {
                            require_once(ABSPATH . '/wp-admin/includes/file.php');
                            WP_Filesystem();
                        }

                        if ($wp_filesystem) {
                            $wp_filesystem->chmod($wrapper, 0700);
                        }
                    }

                    $cmd = 'GIT_SSH=' . escapeshellarg($wrapper) . ' ' . $cmd;
                }
            }

            $cloneResult = SecureGitRunner::cloneRepository($remoteUrl, $absolutePath, ['ssh_key' => $privateKey ?: null]);
            if (! $cloneResult['success']) {
                wp_send_json_error($cloneResult['output'] ?: 'Clone failed - no .git directory found');
            }

            // Handle branch checkout if specified
            $branch = sanitize_text_field(wp_unslash($_POST['repo_branch'] ?? ''));
            if ($branch && 'main' !== $branch && 'master' !== $branch) {
                // Check if the branch exists remotely
                $branchCheckCmd = 'cd ' . escapeshellarg($absolutePath) . ' && git ls-remote --heads origin ' . escapeshellarg($branch);
                if (! GitManager::are_commands_enabled()) {
                    wp_send_json_error('Command execution is disabled');
                }

                $branchCheck  = SecureGitRunner::runInDirectory($absolutePath, 'ls-remote --heads origin ' . escapeshellarg($branch));
                $branchExists = $branchCheck['success'] && !empty($branchCheck['output']);

                if ($branchExists) {
                    // Branch exists remotely, checkout
                    $checkoutCmd = 'cd ' . escapeshellarg($absolutePath) . ' && git checkout ' . escapeshellarg($branch);
                    if (! GitManager::are_commands_enabled()) {
                        wp_send_json_error('Command execution is disabled');
                    }

                    $checkoutResult = SecureGitRunner::runInDirectory($absolutePath, 'checkout ' . escapeshellarg($branch));
                    $checkoutOut    = $checkoutResult['output'] ?? '';
                } else {
                    // Try to create the branch
                    $createCmd = 'cd ' . escapeshellarg($absolutePath) . ' && git checkout -b ' . escapeshellarg($branch);
                    if (! GitManager::are_commands_enabled()) {
                        wp_send_json_error('Command execution is disabled');
                    }

                    $createResult = SecureGitRunner::runInDirectory($absolutePath, 'checkout -b ' . escapeshellarg($branch));
                    $createOut    = $createResult['output'] ?? '';
                }
            }

            $data['path']      = $absolutePath;
            $data['remoteUrl'] = $remoteUrl;
        }

        $repo = $this->repositoryManager->add($data);

        // Handle credentials if provided
        $authType   = sanitize_text_field(wp_unslash($_POST['authType'] ?? 'ssh'));
        $username   = sanitize_text_field(wp_unslash($_POST['username'] ?? ''));
        $token      = sanitize_text_field(wp_unslash($_POST['token'] ?? ''));
        $privateKey = empty($_POST['private_key']) ? '' : sanitize_textarea_field(wp_unslash($_POST['private_key']));

        if ('https' === $authType && ($username || $token)) {
            $cred = ['authType' => $authType];
            if ($username) {
                $cred['username'] = $username;
            }

            if ($token) {
                $cred['token'] = $token;
            }

            if (count($cred) > 1) {
                CredentialStore::set($repo->id, $cred);
            }
        } elseif ('ssh' === $authType && $privateKey) {
            $cred = ['authType' => $authType, 'private_key' => $privateKey];
            CredentialStore::set($repo->id, $cred);
        }

        wp_send_json_success($repo->toArray());
    }

    public function update(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');

        $id = $this->getRepositoryId();

        // Get the current repository to validate changes
        $currentRepo = $this->repositoryManager->get($id);
        if (!$currentRepo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Get new data from POST
        $name       = sanitize_text_field(wp_unslash($_POST['name'] ?? ''));
        $remoteUrl  = sanitize_text_field(wp_unslash($_POST['remoteUrl'] ?? ''));
        $authType   = sanitize_text_field(wp_unslash($_POST['authType'] ?? ''));
        $username   = sanitize_text_field(wp_unslash($_POST['username'] ?? ''));
        $token      = sanitize_text_field(wp_unslash($_POST['token'] ?? ''));
        $privateKey = empty($_POST['private_key']) ? '' : sanitize_textarea_field(wp_unslash($_POST['private_key']));
        $autoDeploy = wp_validate_boolean(wp_unslash($_POST['autoDeploy'] ?? false));
        $webhook    = sanitize_text_field(wp_unslash($_POST['webhook'] ?? ''));

        // Update repository details
        $repo = RepositoryManager::update($id, $name, $remoteUrl, $autoDeploy, $webhook);
        if (! $repo instanceof Repository) {
            wp_send_json_error('Failed to update repository.');
        }

        // Update credentials
        $cred = [
            'authType' => $authType,
            'username' => $username,
            'token'    => $token,
        ];
        if ($privateKey) {
            $cred['private_key'] = $privateKey;
        }
        CredentialStore::set($repo->id, $cred);

        wp_send_json_success($repo->toArray());
    }

    public function delete(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');

        $id = $this->getRepositoryId();

        $manager = RepositoryManager::instance();
        $repo    = $manager->get($id);

        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        $repo_name = $repo->name;

        // Delete from RepositoryManager
        if (! $manager->delete($id)) {
            wp_send_json_error('Failed to remove repository from manager');
        }

        // Always keep repository files on disk; only remove from Repo Manager
        wp_send_json_success(sprintf('Repository "%s" has been removed from Repo Manager successfully', $repo_name));
    }

    /**
     * Recursively delete a directory
     */
    private function delete_directory($path): bool
    {
        if (! is_dir($path)) {
            return false;
        }

        $files = array_diff(scandir($path), ['.', '..']);

        foreach ($files as $file) {
            $file_path = $path . DIRECTORY_SEPARATOR . $file;

            if (is_dir($file_path)) {
                if (! $this->delete_directory($file_path)) {
                    return false;
                }
            } elseif (! wp_delete_file($file_path)) {
                return false;
            }
        }

        // Use WP_Filesystem instead of rmdir
        global $wp_filesystem;
        if (empty($wp_filesystem)) {
            require_once(ABSPATH . '/wp-admin/includes/file.php');
            WP_Filesystem();
        }

        if ($wp_filesystem) {
            return $wp_filesystem->rmdir($path);
        }

        // Use WordPress filesystem as fallback
        if (function_exists('WP_Filesystem')) {
            global $wp_filesystem;
            if (empty($wp_filesystem)) {
                require_once(ABSPATH . '/wp-admin/includes/file.php');
                WP_Filesystem();
            }

            if ($wp_filesystem) {
                return $wp_filesystem->rmdir($path);
            }
        }

        return false; // Don't use direct PHP functions
    }

    public function clone(): void
    {
        check_ajax_referer('git_manager_action', 'nonce');

        $remote     = sanitize_text_field(wp_unslash($_POST['remote'] ?? ''));
        $target     = sanitize_text_field(wp_unslash($_POST['target'] ?? ''));
        $name       = sanitize_text_field(wp_unslash($_POST['name'] ?? ''));
        $authType   = sanitize_text_field(wp_unslash($_POST['authType'] ?? 'ssh'));
        $username   = sanitize_text_field(wp_unslash($_POST['username'] ?? ''));
        $token      = sanitize_text_field(wp_unslash($_POST['token'] ?? ''));
        $privateKey = empty($_POST['private_key']) ? '' : sanitize_textarea_field(wp_unslash($_POST['private_key']));

        if (! $remote || ! $target || ! $name) {
            wp_send_json_error('Missing required data');
        }

        // Construct absolute path if relative path is provided
        $absoluteTarget = $target;
        if (! path_is_absolute($target)) {
            $absoluteTarget = ABSPATH . ltrim($target, '/');
        }

        // Add repository name to the target path
        $absoluteTarget = rtrim($absoluteTarget, '/\\') . DIRECTORY_SEPARATOR . $name;

        if (! RepositoryManager::instance()->validatePath(dirname($absoluteTarget))) {
            wp_send_json_error('Invalid target parent directory');
        }

        // Prepare environment for Git
        $home      = getenv('HOME') ?: (getenv('USERPROFILE') ?: sys_get_temp_dir());
        $homeClean = str_replace('"', '', $home);
        $env       = [];
        $remoteUrl = $remote;
        if ('https' === $authType && $username && $token) {
            $remoteUrl = preg_replace('#^https://#', 'https://' . rawurlencode($username) . ':' . rawurlencode($token) . '@', $remoteUrl);
        }

        if ('WIN' === strtoupper(substr(PHP_OS, 0, 3))) {
            $envStr = '';
            foreach ($env as $key => $value) {
                $envStr .= sprintf('set "%s=%s" && ', $key, $value);
            }

            $cmd = $envStr . 'set "HOME=' . $homeClean . '" && git clone ' . escapeshellarg($remoteUrl) . ' ' . escapeshellarg($absoluteTarget) . ' 2>&1';
        } else {
            $envStr = '';
            foreach ($env as $key => $value) {
                $envStr .= $key . '=' . escapeshellarg($value) . ' ';
            }

            $cmd = $envStr . 'HOME=' . escapeshellarg($home) . ' git clone ' . escapeshellarg($remoteUrl) . ' ' . escapeshellarg($absoluteTarget) . ' 2>&1';
        }

        // If SSH with private key is provided, create a temporary wrapper and prefix GIT_SSH
        if ('ssh' === $authType && $privateKey) {
            $tmpDir = wp_upload_dir(null, false)['basedir'] . '/repo-manager-keys';
            if (! is_dir($tmpDir)) {
                @wp_mkdir_p($tmpDir);
            }

            $keyPath = $tmpDir . '/key_' . md5($privateKey) . '.pem';
            if (! file_exists($keyPath)) {
                file_put_contents($keyPath, $privateKey);
                // Use WP_Filesystem instead of chmod
                global $wp_filesystem;
                if (empty($wp_filesystem)) {
                    require_once(ABSPATH . '/wp-admin/includes/file.php');
                    WP_Filesystem();
                }

                if ($wp_filesystem) {
                    $wp_filesystem->chmod($keyPath, 0600);
                }
            }

            $isWin   = 'WIN' === strtoupper(substr(PHP_OS, 0, 3));
            $wrapper = $tmpDir . '/ssh_wrapper_' . md5($keyPath) . ($isWin ? '.bat' : '.sh');
            if ($isWin) {
                if (! file_exists($wrapper)) {
                    file_put_contents($wrapper, "@echo off\nssh -i \"{$keyPath}\" -o StrictHostKeyChecking=no %*\n");
                }

                $cmd = 'set "GIT_SSH=' . $wrapper . '" && ' . $cmd;
            } else {
                if (! file_exists($wrapper)) {
                    file_put_contents($wrapper, "#!/bin/sh\nexec ssh -i '{$keyPath}' -o StrictHostKeyChecking=no \"$@\"\n");
                    // Use WP_Filesystem instead of chmod
                    global $wp_filesystem;
                    if (empty($wp_filesystem)) {
                        require_once(ABSPATH . '/wp-admin/includes/file.php');
                        WP_Filesystem();
                    }

                    if ($wp_filesystem) {
                        $wp_filesystem->chmod($wrapper, 0700);
                    }
                }

                $cmd = 'GIT_SSH=' . escapeshellarg($wrapper) . ' ' . $cmd;
            }
        }

        if (! GitManager::are_commands_enabled()) {
            wp_send_json_error('Command execution is disabled');
        }

        $cloneResult = SecureGitRunner::cloneRepository($remoteUrl, $absoluteTarget, ['ssh_key' => $privateKey ?: null]);
        if (! $cloneResult['success']) {
            wp_send_json_error($cloneResult['output'] ?: 'Clone failed - no .git directory found');
        }

        $repo = $this->repositoryManager->add([
            'name'      => $name,
            'path'      => $absoluteTarget,
            'remoteUrl' => $remote,
            'authType'  => $authType,
        ]);
        // Save credentials if provided
        $cred = ['authType' => $authType];
        if ('https' === $authType) {
            if ($username) {
                $cred['username'] = $username;
            } if ($token) {
                $cred['token'] = $token;
            }
        }

        if ('ssh' === $authType && $privateKey) {
            $cred['private_key'] = $privateKey;
        }

        if (count($cred) > 1) {
            CredentialStore::set($repo->id, $cred);
        }

        wp_send_json_success(['output' => $cloneResult['output'], 'repository' => $repo->toArray()]);
    }

    /** Add existing repository (no clone) */
    public function addExisting(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $name       = sanitize_text_field(wp_unslash($_POST['name'] ?? ''));
        $path       = sanitize_text_field(wp_unslash($_POST['path'] ?? ''));
        $remoteUrl  = sanitize_text_field(wp_unslash($_POST['remoteUrl'] ?? ''));
        $authType   = sanitize_text_field(wp_unslash($_POST['authType'] ?? 'ssh'));
        $username   = sanitize_text_field(wp_unslash($_POST['username'] ?? ''));
        $token      = sanitize_text_field(wp_unslash($_POST['token'] ?? ''));
        $privateKey = empty($_POST['private_key']) ? '' : sanitize_textarea_field(wp_unslash($_POST['private_key']));
        if (! $name || ! $path) {
            wp_send_json_error('Name and path are required');
        }

        // Construct absolute path if relative path is provided
        $absolutePath = $path;
        if (! path_is_absolute($path)) {
            $absolutePath = ABSPATH . ltrim($path, '/');
        }

        if (! RepositoryManager::instance()->validatePath($absolutePath)) {
            wp_send_json_error('Invalid path');
        }

        if (! \WPGitManager\Service\SecureGitRunner::isGitRepositoryPath($absolutePath)) {
            wp_send_json_error('Selected path is not a Git repository');
        }

        $repo = $this->repositoryManager->add([
            'name'      => $name,
            'path'      => realpath($absolutePath),
            'remoteUrl' => $remoteUrl ?: null,
            'authType'  => $authType,
        ]);
        $cred = ['authType' => $authType];
        if ('https' === $authType) {
            if ($username) {
                $cred['username'] = $username;
            } if ($token) {
                $cred['token'] = $token;
            }
        }

        if ('ssh' === $authType && $privateKey) {
            $cred['private_key'] = $privateKey;
        }

        if (count($cred) > 1) {
            CredentialStore::set($repo->id, $cred);
        }

        wp_send_json_success($repo->toArray());
    }

    public function gitOp(): void
    {
        $this->ensureAllowed();

        // Verify nonce
        check_ajax_referer('git_manager_action', 'nonce');

        $id   = $this->getRepositoryId();
        $op   = sanitize_text_field(wp_unslash($_POST['op'] ?? 'status'));
        $repo = $this->repositoryManager->get($id);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        $map = [
            'fetch'    => 'fetch --all --prune',
            'pull'     => 'pull --ff-only',
            'push'     => 'push',
            'status'   => 'status --short --branch',
            'branches' => 'branch -a',
            'log'      => 'log -n 10 --pretty=format:"%h|%an|%ar|%s"',
            'tags'     => 'tag --list',
            'stash'    => 'stash list',
        ];

        $cmd = $map[$op] ?? null;
        if (! $cmd) {
            wp_send_json_error('Unsupported operation');
        }

        $opts = [];
        if (in_array($op, ['fetch', 'pull', 'push'], true)) {
            $opts['low_priority'] = true;
        }

        $res = GitCommandRunner::run($repo->path, $cmd, $opts);

        // Invalidate caches for mutating ops
        if (in_array($op, ['fetch', 'pull', 'push'], true)) {
            delete_transient('git_manager_cache_repo_list');
            delete_transient('git_manager_cache_repo_status_' . $id);
            delete_transient('git_manager_cache_repo_details_' . $id);
            delete_transient('git_manager_cache_latest_commit_' . $id);
            // Invalidate commits cache for this repository
            $this->invalidateCommitsCache($id);
        }

        wp_send_json_success($res);
    }

    private function sanitizeRef(string $ref): string
    {
        return preg_replace('/[^A-Za-z0-9._\-\/]/', '', $ref);
    }

    public function checkout(): void
    {
        // Try multiple nonce verification methods like latestCommit
        if (! current_user_can('manage_options')) {
            wp_send_json_error('Access denied');
        }

        $nonce                 = sanitize_text_field(sanitize_text_field(wp_unslash($_POST['nonce'] ?? '')));
        $action_specific_valid = wp_verify_nonce($nonce, 'git_manager_action');
        $general_nonce_valid   = wp_verify_nonce($nonce, 'git_manager_action');

        if (! $action_specific_valid && ! $general_nonce_valid) {
            wp_send_json_error('Invalid nonce');
        }

        $id     = $this->getRepositoryId();
        $branch = $this->sanitizeRef(sanitize_text_field(wp_unslash($_POST['branch'] ?? '')));
        $repo   = $this->repositoryManager->get($id);
        if (! $repo || ! $branch) {
            wp_send_json_error('Invalid data');
        }

        // Check if repository is clean before attempting checkout
        $statusResult = GitCommandRunner::run($repo->path, 'status --porcelain');
        if (!in_array(trim($statusResult['output']), ['', '0'], true)) {
            wp_send_json_error('Cannot checkout: Repository has uncommitted changes. Please commit or stash your changes first.');
        }

        // Fetch first to ensure we have latest remote branches
        GitCommandRunner::run($repo->path, 'fetch --all');

        // Determine if local branch exists
        $localCheck = GitCommandRunner::run($repo->path, 'show-ref --heads ' . escapeshellarg('refs/heads/' . $branch));

        if (! empty($localCheck['output'])) {
            // Local branch exists, just checkout
            $res = GitCommandRunner::run($repo->path, 'checkout ' . escapeshellarg($branch));
        } else {
            // Try to checkout remote branch
            $res = GitCommandRunner::run($repo->path, 'checkout -b ' . escapeshellarg($branch) . ' origin/' . escapeshellarg($branch));

            // If that fails, try creating a new branch
            if (($res['exitCode'] ?? 0) !== 0) {
                $res = GitCommandRunner::run($repo->path, 'checkout -b ' . escapeshellarg($branch));
            }
        }

        // Verify that checkout was successful by checking current branch
        $currentBranchResult = GitCommandRunner::run($repo->path, 'rev-parse --abbrev-ref HEAD');
        $currentBranch       = trim($currentBranchResult['output']);

        if ($currentBranch !== $branch) {
            wp_send_json_error('Checkout failed: Could not switch to branch ' . $branch . '. Current branch is: ' . $currentBranch);
        }

        // Invalidate caches so other pages (dashboard) see the new branch immediately
        delete_transient('git_manager_cache_repo_list');
        delete_transient('git_manager_cache_repo_status_' . $id);
        delete_transient('git_manager_cache_repo_details_' . $id);
        delete_transient('git_manager_cache_latest_commit_' . $id);
        // Invalidate commits cache for this repository
        $this->invalidateCommitsCache($id);

        wp_send_json_success($res);
    }

    public function createBranch(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id         = $this->getRepositoryId();
        $branchName = $this->sanitizeRef(sanitize_text_field(wp_unslash($_POST['branch'] ?? '')));
        $repo       = $this->repositoryManager->get($id);

        if (! $repo || ! $branchName) {
            wp_send_json_error('Invalid branch name');
        }

        $res = GitCommandRunner::run($repo->path, 'checkout -b ' . escapeshellarg($branchName));
        wp_send_json_success($res);
    }

    public function deleteBranch(): void
    {
        $this->ensureAllowed();

        // Verify nonce
        check_ajax_referer('git_manager_action', 'nonce');

        $id         = $this->getRepositoryId();
        $branchName = $this->sanitizeRef(sanitize_text_field(wp_unslash($_POST['branch'] ?? '')));
        $repo       = $this->repositoryManager->get($id);

        if (! $repo || ! $branchName) {
            wp_send_json_error('Invalid branch name');
        }

        // Don't allow deleting current branch
        $current = GitCommandRunner::run($repo->path, 'rev-parse --abbrev-ref HEAD');
        if (trim($current['output']) === $branchName) {
            wp_send_json_error('Cannot delete current branch');
        }

        $res = GitCommandRunner::run($repo->path, 'branch -D ' . escapeshellarg($branchName));
        wp_send_json_success($res);
    }

    public function push(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id     = $this->getRepositoryId();
        $branch = $this->sanitizeRef(sanitize_text_field(wp_unslash($_POST['branch'] ?? '')));
        $repo   = $this->repositoryManager->get($id);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        if ('' === $branch || '0' === $branch) {
            // Detect current branch
            $current = GitCommandRunner::run($repo->path, 'rev-parse --abbrev-ref HEAD');
            $branch  = trim($current['output']);
        }

        $res = GitCommandRunner::run($repo->path, 'push origin ' . escapeshellarg($branch), ['low_priority' => true]);
        // Invalidate caches for this repo
        delete_transient('git_manager_cache_repo_list');
        delete_transient('git_manager_cache_repo_status_' . $id);
        delete_transient('git_manager_cache_repo_details_' . $id);
        delete_transient('git_manager_cache_latest_commit_' . $id);
        // Invalidate commits cache for this repository
        $this->invalidateCommitsCache($id);
        wp_send_json_success($res);
    }

    public function merge(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id     = $this->getRepositoryId();
        $source = $this->sanitizeRef(sanitize_text_field(wp_unslash($_POST['source'] ?? '')));
        $repo   = $this->repositoryManager->get($id);
        if (! $repo || ! $source) {
            wp_send_json_error('Invalid data');
        }

        GitCommandRunner::run($repo->path, 'fetch --all');
        $res = GitCommandRunner::run($repo->path, 'merge ' . escapeshellarg($source));
        wp_send_json_success($res);
    }

    public function createTag(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id      = $this->getRepositoryId();
        $tag     = $this->sanitizeRef(sanitize_text_field(wp_unslash($_POST['tag'] ?? '')));
        $message = sanitize_text_field(wp_unslash($_POST['message'] ?? ''));
        $repo    = $this->repositoryManager->get($id);

        if (! $repo || ! $tag) {
            wp_send_json_error('Invalid tag name');
        }

        $cmd = 'tag ' . escapeshellarg($tag);
        if ($message) {
            $cmd .= ' -m ' . escapeshellarg($message);
        }

        $res = GitCommandRunner::run($repo->path, $cmd);
        wp_send_json_success($res);
    }

    public function stash(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id      = $this->getRepositoryId();
        $message = sanitize_text_field(wp_unslash($_POST['message'] ?? ''));
        $repo    = $this->repositoryManager->get($id);

        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        $cmd = 'stash';
        if ($message) {
            $cmd .= ' push -m ' . escapeshellarg($message);
        }

        $res = GitCommandRunner::run($repo->path, $cmd);
        wp_send_json_success($res);
    }

    public function stashPop(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id   = $this->getRepositoryId();
        $repo = $this->repositoryManager->get($id);

        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        $res = GitCommandRunner::run($repo->path, 'stash pop');
        wp_send_json_success($res);
    }

    /**
     * Get detailed commit information with author and date
     */
    public function detailedLog(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $repoId = $this->getRepositoryId();

        if ('' === $repoId || '0' === $repoId) {
            wp_send_json_error('No repository specified');
        }

        $repo = $this->repositoryManager->get($repoId);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Get current branch first
        $branchResult = GitCommandRunner::run($repo->path, 'rev-parse --abbrev-ref HEAD');
        if (! $branchResult['success']) {
            // Fallback: try to get branch from status
            $statusResult = GitCommandRunner::run($repo->path, 'status --porcelain --branch');
            if ($statusResult['success']) {
                $lines = explode("\n", trim($statusResult['output'] ?? ''));
                foreach ($lines as $line) {
                    if (0 === strpos($line, '##') && preg_match('/## ([^\.]+)/', $line, $matches)) {
                        $currentBranch = $matches[1];
                        break;
                    }
                }
            }

            if ('0' === $currentBranch) {
                wp_send_json_error('Failed to get current branch');
            }
        } else {
            $currentBranch = trim($branchResult['output']);
        }

        // Get latest commit for current branch
        $result = GitCommandRunner::run($repo->path, sprintf('log -1 --format="%%H|%%an|%%ae|%%s" %s', $currentBranch));
        if (! $result['success']) {
            wp_send_json_error('Failed to get latest commit');
        }

        $parts = explode('|', trim($result['output']));
        if (4 !== count($parts)) {
            wp_send_json_error('Invalid commit format');
        }

        // Get avatar information using author name and email
        $authorString = $parts[1] . ' <' . $parts[2] . '>';
        $avatarInfo   = $this->getGravatarUrl($authorString);

        $data = [
            'hash'         => $parts[0],
            'author'       => $parts[1],
            'author_name'  => $parts[1],
            'author_email' => $parts[2],
            'subject'      => $parts[3],
            'branch'       => $currentBranch,
            'repo_name'    => $repo->name,
            'gravatar_url' => $avatarInfo['gravatar_url'],
            'has_avatar'   => $avatarInfo['has_avatar'],
        ];

        // Get remote hash if available for current branch
        $remoteResult = GitCommandRunner::run($repo->path, 'rev-parse origin/' . $currentBranch);
        if ($remoteResult['success']) {
            $data['remote_hash'] = trim($remoteResult['output']);
        }

        wp_send_json_success($data);
    }

    public function setActive(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id = $this->getRepositoryId();
        $ok = $this->repositoryManager->setActive($id);
        $ok ? wp_send_json_success(true) : wp_send_json_error('Repository not found');
    }

    public function troubleshootRepo(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id   = $this->getRepositoryId();
        $repo = $this->repositoryManager->get($id);
        if (! $repo || ! is_dir($repo->path)) {
            wp_send_json_error('Invalid repository');
        }

        $path = $repo->path;
        $html = '';
        // 1) Git binary
        $gitVersionRes = SecureGitRunner::gitVersion();
        $gitVersion    = ($gitVersionRes['success']) ? trim((string) $gitVersionRes['output']) : '';
        $html .= '<b>Git:</b> ' . ($gitVersion ?: 'Not found') . '\n';
        // 2) Repo path and .git
        $html .= is_dir($path) ? "\nRepo Path: OK (" . esc_html($path) . ')' : "\nRepo Path: NOT FOUND";
        $html .= is_dir($path . '/.git') ? "\n.git: OK" : "\n.git: MISSING";
        // 3) Safe directory attempt
        if (is_dir($path . '/.git')) {
            if (GitManager::are_commands_enabled()) {
                $safeRes = SecureGitRunner::setLocalSafeDirectory($path);
                $outSafe = $safeRes['output'] ?? '';
                $html .= "\nSafe Directory: " . ('' === trim($outSafe) ? 'OK (set)' : 'Tried (' . esc_html($outSafe) . ')');
            } else {
                $html .= "\nSafe Directory: skipped (commands disabled)";
            }
        }

        // 4) Remote test
        $remoteUrlRes = SecureGitRunner::getRemoteOriginUrl($path);
        $remoteUrl    = $remoteUrlRes['success'] ? trim((string) ($remoteUrlRes['output'] ?? '')) : '';
        if ('' !== $remoteUrl && '0' !== $remoteUrl) {
            $ls = GitCommandRunner::run($path, 'ls-remote --exit-code origin');
            $html .= "\nRemote: " . $remoteUrl . "\nRemote check: " . (false !== strpos($ls['output'] ?? '', 'fatal:') ? 'Failed' : 'OK');
        } else {
            $html .= "\nRemote: not set";
        }

        wp_send_json_success(['html' => nl2br($html)]);
    }

    /** Simple directory lister for picker (restrict within ABSPATH by default) */
    public function listDirectories(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $relative = sanitize_text_field(wp_unslash($_POST['relative'] ?? ''));
        $query    = sanitize_text_field(wp_unslash($_POST['query'] ?? ''));

        $base = realpath(ABSPATH);

        // If search query is provided, search from root
        if (! empty($query)) {
            $this->searchDirectories($base, $query);

            return;
        }

        $target = realpath($base . ($relative ? DIRECTORY_SEPARATOR . $relative : ''));

        if (! $target || 0 !== strpos($target, (string) $base)) {
            wp_send_json_error('Invalid path');
        }

        $items   = @scandir($target) ?: [];
        $dirs    = [];
        $skip    = $this->getGitIgnored($base);
        $maxRows = 300; // keep payloads small for faster UI
        $baseLen = strlen((string) $base);

        foreach ($items as $item) {
            if ('.' === $item || '..' === $item) {
                continue;
            }

            if (in_array($item, $skip, true)) {
                continue;
            }

            $full = $target . DIRECTORY_SEPARATOR . $item;
            if (is_dir($full)) {
                $relativePath = ltrim(substr($full, $baseLen), '\/');
                $dirs[]       = [
                    'name'     => $item,
                    'relative' => $relativePath,
                ];
                if (count($dirs) >= $maxRows) {
                    break;
                }
            }
        }

        wp_send_json_success([
            'cwd'  => ltrim(substr($target, $baseLen), '\/'),
            'dirs' => $dirs,
        ]);
    }

    /** Search directories recursively */
    private function searchDirectories(string $base, string $query): void
    {
        // Cache search results based on query to avoid repeated deep scans
        $cacheKey = 'git_manager_cache_dirsearch_' . md5($base . '|' . strtolower($query));
        $cached   = get_transient($cacheKey);
        if (false !== $cached) {
            wp_send_json_success($cached);
        }

        $results = [];
        $this->searchDirectoriesRecursive($base, $query, $results, $base);

        // Limit results size and sort for stable UI
        $maxResults = 1000;
        if (count($results) > $maxResults) {
            $results = array_slice($results, 0, $maxResults);
        }
        usort($results, static function ($a, $b) {
            return strnatcasecmp($a['name'], $b['name']);
        });

        $response = [
            'cwd'  => '',
            'dirs' => $results,
        ];

        set_transient($cacheKey, $response, 10 * MINUTE_IN_SECONDS);
        wp_send_json_success($response);
    }

    private function searchDirectoriesRecursive(string $dir, string $query, array &$results, string $base): void
    {
        if (! is_dir($dir)) {
            return;
        }

        // Avoid massive scans: skip heavy/hidden directories and limit total results
        $skip  = $this->getGitIgnored($base);
        $limit = 2000; // hard cap to avoid long responses
        if (count($results) >= $limit) {
            return;
        }

        $items = @scandir($dir) ?: [];
        foreach ($items as $item) {
            if ('.' === $item || '..' === $item) {
                continue;
            }

            $full = $dir . DIRECTORY_SEPARATOR . $item;
            if (in_array($item, $skip, true)) {
                continue;
            }

            if (is_link($full)) {
                // Skip symlinks to prevent loops
                continue;
            }

            if (is_dir($full)) {
                // Check if directory name matches query
                if (false !== stripos($item, $query)) {
                    $relative  = ltrim(str_replace($base, '', $full), '\/');
                    $results[] = [
                        'name'     => $item,
                        'relative' => $relative,
                        'fullPath' => $relative, // Add full path for search results
                    ];
                    if (count($results) >= $limit) {
                        return;
                    }
                }

                // Continue searching in subdirectories (limit depth to avoid performance issues)
                $depth = substr_count(str_replace($base, '', $full), DIRECTORY_SEPARATOR);
                if ($depth < 5) { // Limit search depth to 5 levels
                    $this->searchDirectoriesRecursive($full, $query, $results, $base);
                }
            }
        }
    }

    /**
     * Get a list of ignored directories from the root .gitignore file
     */
    private function getGitIgnored(string $base): array
    {
        $ignored = ['.git', 'node_modules', 'vendor', '.cache', '.svn', '.idea', '.vscode']; // Defaults
        $ignoreFile = $base . '/.gitignore';

        if (is_readable($ignoreFile)) {
            $lines = file($ignoreFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (false !== $lines) {
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ('' === $line || '#' === $line[0]) {
                        continue;
                    }
                    // Simple parser: remove trailing slashes and comments
                    $line      = rtrim($line, '/');
                    $commentPos = strpos($line, '#');
                    if (false !== $commentPos) {
                        $line = trim(substr($line, 0, $commentPos));
                    }
                    if (! empty($line)) {
                        $ignored[] = $line;
                    }
                }
            }
        }

        return array_unique($ignored);
    }

    /** Create a directory within allowed root (default ABSPATH) */
    public function createDirectory(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $relative = sanitize_text_field(wp_unslash($_POST['relative'] ?? ''));
        $name     = sanitize_file_name(wp_unslash($_POST['name'] ?? ''));

        if ('' === $name || preg_match('/[\\\/:*?"<>|]/', $name)) {
            wp_send_json_error('Invalid folder name');
        }

        $base   = realpath(ABSPATH);
        $parent = realpath($base . ($relative ? DIRECTORY_SEPARATOR . $relative : ''));
        if (! $parent || 0 !== strpos($parent, (string) $base)) {
            wp_send_json_error('Invalid path');
        }

        $target = $parent . DIRECTORY_SEPARATOR . $name;
        if (file_exists($target)) {
            wp_send_json_error('Folder already exists');
        }

        if (! wp_mkdir_p($target)) {
            wp_send_json_error('Failed to create folder');
        }

        wp_send_json_success(['message' => 'Folder created', 'relative' => ltrim(str_replace($base, '', $target), '\\/')]);
    }

    /** Delete an empty directory within allowed root (default ABSPATH) */
    public function deleteDirectory(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $relative = sanitize_text_field(wp_unslash($_POST['relative'] ?? ''));

        $base   = realpath(ABSPATH);
        $target = realpath($base . ($relative ? DIRECTORY_SEPARATOR . $relative : ''));
        if (! $target || 0 !== strpos($target, (string) $base)) {
            wp_send_json_error('Invalid path');
        }

        // Block deleting core directories and ensure directory is empty
        if (! is_dir($target)) {
            wp_send_json_error('Not a directory');
        }

        $restricted = [realpath(ABSPATH), realpath(WP_CONTENT_DIR), realpath(WP_PLUGIN_DIR)];
        foreach ($restricted as $r) {
            if ($r && $target === $r) {
                wp_send_json_error('Cannot delete protected directory');
            }
        }

        $files = @array_diff(scandir($target) ?: [], ['.', '..']);
        if ([] !== $files) {
            wp_send_json_error('Directory is not empty');
        }

        // Use WP_Filesystem instead of rmdir
        global $wp_filesystem;
        if (empty($wp_filesystem)) {
            require_once(ABSPATH . '/wp-admin/includes/file.php');
            WP_Filesystem();
        }

        if ($wp_filesystem && ! $wp_filesystem->rmdir($target)) {
            wp_send_json_error('Failed to delete directory');
        }

        // Don't use direct PHP functions as fallback
        if (! $wp_filesystem) {
            wp_send_json_error('WordPress filesystem not available');
        }

        wp_send_json_success(['message' => 'Folder deleted']);
    }

    /** Rename a directory within allowed root (default ABSPATH) */
    public function renameDirectory(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $relative = sanitize_text_field(wp_unslash($_POST['relative'] ?? ''));
        $newName  = sanitize_file_name(wp_unslash($_POST['new_name'] ?? ''));

        if ('' === $newName || preg_match('/[\\\/:*?"<>|]/', $newName)) {
            wp_send_json_error('Invalid folder name');
        }

        $base   = realpath(ABSPATH);
        $target = realpath($base . ($relative ? DIRECTORY_SEPARATOR . $relative : ''));
        if (! $target || 0 !== strpos($target, (string) $base)) {
            wp_send_json_error('Invalid path');
        }

        if (! is_dir($target)) {
            wp_send_json_error('Not a directory');
        }

        // Block renaming core directories
        $restricted = [realpath(ABSPATH), realpath(WP_CONTENT_DIR), realpath(WP_PLUGIN_DIR)];
        foreach ($restricted as $r) {
            if ($r && $target === $r) {
                wp_send_json_error('Cannot rename protected directory');
            }
        }

        $parent    = dirname($target);
        $newTarget = $parent . DIRECTORY_SEPARATOR . $newName;

        if (file_exists($newTarget)) {
            wp_send_json_error('Folder with this name already exists');
        }

        // Use WP_Filesystem instead of rename
        global $wp_filesystem;
        if (empty($wp_filesystem)) {
            require_once(ABSPATH . '/wp-admin/includes/file.php');
            WP_Filesystem();
        }

        if ($wp_filesystem && ! $wp_filesystem->move($target, $newTarget)) {
            wp_send_json_error('Failed to rename directory');
        }

        // Don't use direct PHP functions as fallback
        if (! $wp_filesystem) {
            wp_send_json_error('WordPress filesystem not available');
        }

        wp_send_json_success(['message' => 'Folder renamed']);
    }

    // Admin bar compatibility methods
    public function latestCommit(): void
    {
        // Check permissions first
        if (! current_user_can('manage_options')) {
            wp_send_json_error('Access denied');
        }

        check_ajax_referer('git_manager_action', 'nonce');

        $repoId = $this->getRepositoryId();

        if ('' === $repoId || '0' === $repoId) {
            // Fallback to active repository for backward compatibility
            $repoId = $this->repositoryManager->getActiveId();
        }

        if (! $repoId) {
            wp_send_json_error('No repository specified');
        }

        $repo = $this->repositoryManager->get($repoId);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Cache-first
        $cacheKey = 'git_manager_cache_latest_commit_' . $repoId;
        $cached   = get_transient($cacheKey);
        if (false !== $cached) {
            wp_send_json_success($cached);
        }

        // Get current branch first
        $currentBranch = '0'; // Initialize with default value
        $branchResult  = GitCommandRunner::run($repo->path, 'rev-parse --abbrev-ref HEAD');
        if (! $branchResult['success']) {
            // Fallback: try to get branch from status
            $statusResult = GitCommandRunner::run($repo->path, 'status --porcelain --branch');
            if ($statusResult['success']) {
                $lines = explode("\n", trim($statusResult['output'] ?? ''));
                foreach ($lines as $line) {
                    if (0 === strpos($line, '##') && preg_match('/## ([^\.]+)/', $line, $matches)) {
                        $currentBranch = $matches[1];
                        break;
                    }
                }
            }

            if ('0' === $currentBranch) {
                wp_send_json_error('Failed to get current branch');
            }
        } else {
            $currentBranch = trim($branchResult['output']);
        }

        // Get latest commit for current branch
        $result = GitCommandRunner::run($repo->path, sprintf('log -1 --format="%%H|%%an|%%ae|%%s" %s', $currentBranch));
        if (! $result['success']) {
            wp_send_json_error('Failed to get latest commit');
        }

        $parts = explode('|', trim($result['output']));
        if (4 !== count($parts)) {
            wp_send_json_error('Invalid commit format');
        }

        // Get avatar information using author name and email
        $authorString = $parts[1] . ' <' . $parts[2] . '>';
        $avatarInfo   = $this->getGravatarUrl($authorString);

        $data = [
            'hash'         => $parts[0],
            'author'       => $parts[1],
            'author_name'  => $parts[1],
            'author_email' => $parts[2],
            'subject'      => $parts[3],
            'branch'       => $currentBranch,
            'repo_name'    => $repo->name,
            'gravatar_url' => $avatarInfo['gravatar_url'],
            'has_avatar'   => $avatarInfo['has_avatar'],
        ];

        // Get remote hash if available for current branch
        $remoteResult = GitCommandRunner::run($repo->path, 'rev-parse origin/' . $currentBranch);
        if ($remoteResult['success']) {
            $data['remote_hash'] = trim($remoteResult['output']);
        }

        set_transient($cacheKey, $data, 15);
        wp_send_json_success($data);
    }

    public function fetch(): void
    {
        // Try multiple nonce verification methods like latestCommit
        if (! current_user_can('manage_options')) {
            wp_send_json_error('Access denied');
        }

        check_ajax_referer('git_manager_action', 'nonce');

        $repoId = $this->getRepositoryId();
        if ('' === $repoId || '0' === $repoId) {
            // Fallback to active repository for backward compatibility
            $repoId = $this->repositoryManager->getActiveId();
        }

        if (! $repoId) {
            wp_send_json_error('No repository specified');
        }

        $repo = $this->repositoryManager->get($repoId);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        $result = GitCommandRunner::run($repo->path, 'fetch --all --prune', ['low_priority' => true]);
        // Invalidate caches for this repo
        delete_transient('git_manager_cache_repo_list');
        delete_transient('git_manager_cache_repo_status_' . $repoId);
        delete_transient('git_manager_cache_repo_details_' . $repoId);
        delete_transient('git_manager_cache_latest_commit_' . $repoId);
        // Invalidate commits cache for this repository
        $this->invalidateCommitsCache($repoId);
        if ($result['success']) {
            wp_send_json_success(['message' => 'Repository fetched successfully']);
        } else {
            wp_send_json_error('Failed to fetch repository: ' . $result['output']);
        }
    }

    public function pull(): void
    {
        // Try multiple nonce verification methods like latestCommit
        if (! current_user_can('manage_options')) {
            wp_send_json_error('Access denied');
        }

        check_ajax_referer('git_manager_action', 'nonce');

        $repoId = $this->getRepositoryId();
        if ('' === $repoId || '0' === $repoId) {
            // Fallback to active repository for backward compatibility
            $repoId = $this->repositoryManager->getActiveId();
        }

        if (! $repoId) {
            wp_send_json_error('No repository specified');
        }

        $repo = $this->repositoryManager->get($repoId);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        $result = GitCommandRunner::run($repo->path, 'pull --ff-only', ['low_priority' => true]);
        // Invalidate caches for this repo
        delete_transient('git_manager_cache_repo_list');
        delete_transient('git_manager_cache_repo_status_' . $repoId);
        delete_transient('git_manager_cache_repo_details_' . $repoId);
        delete_transient('git_manager_cache_latest_commit_' . $repoId);
        // Invalidate commits cache for this repository
        $this->invalidateCommitsCache($repoId);
        if ($result['success']) {
            wp_send_json_success(['message' => 'Repository pulled successfully']);
        } else {
            wp_send_json_error('Failed to pull repository: ' . $result['output']);
        }
    }

    public function ajax_get_branches(): void
    {
        $this->ensureAllowed();
        check_ajax_referer('git_manager_action', 'nonce');
        $id   = $this->getRepositoryId();
        $repo = $this->repositoryManager->get($id);
        if (!$repo) {
            wp_send_json_error('Repository not found');
        }

        $localResult = GitCommandRunner::run($repo->path, 'branch');
        if (!$localResult['success']) {
            wp_send_json_error('Failed to get local branches');
        }

        $remoteResult = GitCommandRunner::run($repo->path, 'branch -r');
        if (!$remoteResult['success']) {
            wp_send_json_error('Failed to get remote branches');
        }

        $activeBranchResult = GitCommandRunner::run($repo->path, 'rev-parse --abbrev-ref HEAD');
        $activeBranch       = $activeBranchResult['success'] ? trim($activeBranchResult['output']) : '';

        $localBranches = array_values(array_filter(array_map(function ($b) {
            return trim(str_replace('* ', '', $b));
        }, explode("\n", trim($localResult['output'])))));

        $remoteBranches = array_values(array_filter(array_map(function ($b) {
            $b = trim($b);
            if (strpos($b, '->') === false) {
                return str_replace('origin/', '', $b);
            }
            return null;
        }, explode("\n", trim($remoteResult['output'])))));

        wp_send_json_success([
            'branches'        => array_values(array_unique(array_merge($localBranches, $remoteBranches))),
            'active_branch'   => $activeBranch,
            'local_branches'  => $localBranches,
            'remote_branches' => $remoteBranches,
        ]);
    }

    public function ajax_checkout_branch(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $id     = $this->getRepositoryId();
        $branch = $this->sanitizeRef(sanitize_text_field(wp_unslash($_POST['branch'] ?? '')));
        $repo   = $this->repositoryManager->get($id);
        if (! $repo || ! $branch) {
            wp_send_json_error('Invalid data');
        }

        // --- Improved Checkout Logic ---

        // 1. Check if repository is clean before attempting checkout
        $statusResult = GitCommandRunner::run($repo->path, 'status --porcelain');
        if (!in_array(trim($statusResult['output']), ['', '0'], true)) {
            wp_send_json_error('Cannot checkout: Repository has uncommitted changes. Please commit or stash your changes first.');
        }

        // 2. Fetch first to ensure we have the latest remote branches
        GitCommandRunner::run($repo->path, 'fetch origin', ['low_priority' => true]);

        // 3. Attempt to checkout the branch. Git will handle creating a local tracking branch if it exists on the remote.
        $res = GitCommandRunner::run($repo->path, 'checkout ' . escapeshellarg($branch));

        if (! $res['success']) {
            // Provide a more specific error if checkout failed
            $error = 'Failed to checkout ' . esc_html($branch) . '. Git reported: ' . esc_html($res['output'] ?: 'Unknown error');
            wp_send_json_error($error);
        }

        // Invalidate caches for this repo after checkout
        delete_transient('git_manager_cache_repo_list');
        delete_transient('git_manager_cache_repo_status_' . $id);
        delete_transient('git_manager_cache_repo_details_' . $id);
        delete_transient('git_manager_cache_latest_commit_' . $id);
        // Invalidate commits cache for this repository
        $this->invalidateCommitsCache($id);

        wp_send_json_success($res);
    }

    public function log(): void
    {
        $this->ensureAllowed();
        check_ajax_referer('git_manager_action', 'nonce');
        $id   = $this->getRepositoryId();
        $repo = $this->repositoryManager->get($id);

        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Get number of commits to fetch (default to 10 for better performance)
        $limit = isset($_POST['limit']) ? intval(wp_unslash($_POST['limit'])) : 10;
        $limit = min(max(1, $limit), 50); // Cap at 50 for security

        // Check cache first - cache for 2 minutes to balance freshness vs performance
        $cacheKey = 'git_manager_commits_' . $id . '_' . $limit;
        $cached   = get_transient($cacheKey);
        if (false !== $cached) {
            wp_send_json_success($cached);
        }

        // Check if repository path exists and is a git repository
        if (!is_dir($repo->path)) {
            wp_send_json_error('Repository path does not exist');
        }

        if (! \WPGitManager\Service\SecureGitRunner::isGitRepositoryPath($repo->path)) {
            wp_send_json_error('Not a git repository');
        }

        // Get current branch efficiently
        $currentBranch = $this->getCurrentBranch($repo->path);
        if ('' === $currentBranch || '0' === $currentBranch) {
            wp_send_json_success([]);
            return;
        }

        // Use optimized git command with timeout handling
        $commits = $this->fetchCommitsOptimized($repo->path, $limit);

        if (false === $commits) {
            wp_send_json_error('Failed to fetch commits');
        }

        // Cache the results for 2 minutes and store key in registry to allow invalidation without direct SQL
        set_transient($cacheKey, $commits, 120);
        $registryKey = 'git_manager_commits_registry_' . $id;
        $keys        = get_option($registryKey, []);
        if (!is_array($keys)) {
            $keys = [];
        }

        if (!in_array($cacheKey, $keys, true)) {
            $keys[] = $cacheKey;
            update_option($registryKey, $keys, false);
        }

        wp_send_json_success($commits);
    }

    /**
     * Get current branch efficiently
     */
    private function getCurrentBranch(string $repoPath): string
    {
        // Try the fastest method first
        $branchResult = GitCommandRunner::run($repoPath, 'rev-parse --abbrev-ref HEAD');
        if ($branchResult['success'] && !in_array(trim($branchResult['output']), ['', '0'], true)) {
            return trim($branchResult['output']);
        }

        // Fallback: try to get branch from status
        $statusResult = GitCommandRunner::run($repoPath, 'status --porcelain --branch');
        if ($statusResult['success']) {
            $lines = explode("\n", trim($statusResult['output'] ?? ''));
            foreach ($lines as $line) {
                if (0 === strpos($line, '##') && preg_match('/## ([^\.]+)/', $line, $matches)) {
                    return $matches[1];
                }
            }
        }

        // Last resort: try HEAD
        $headResult = GitCommandRunner::run($repoPath, 'log --oneline -n 1');
        if ($headResult['success'] && !in_array(trim($headResult['output']), ['', '0'], true)) {
            return 'HEAD';
        }

        return '';
    }

    /**
     * Fetch commits with optimized approach and fallbacks
     */
    private function fetchCommitsOptimized(string $repoPath, int $limit)
    {
        // Use optimized format with minimal data for better performance
        $separator = '###';
        $format    = implode($separator, ['%h', '%an', '%ae', '%cr', '%s']);

        // Try the most efficient command first
        $command = sprintf('log --pretty=format:"%s" -n %d --no-merges', $format, $limit);
        $result  = GitCommandRunner::run($repoPath, $command);

        if (!$result['success']) {
            // Fallback 1: Try without --no-merges
            $fallbackCommand = sprintf('log --pretty=format:"%s" -n %d', $format, $limit);
            $result          = GitCommandRunner::run($repoPath, $fallbackCommand);
        }

        if (!$result['success']) {
            // Fallback 2: Try simple oneline format
            $simpleCommand = sprintf('log --oneline -n %d', $limit);
            $result        = GitCommandRunner::run($repoPath, $simpleCommand);

            if (!$result['success']) {
                return false;
            }

            // Parse simple format
            return $this->parseSimpleCommits($result['output']);
        }

        // Parse detailed format
        return $this->parseDetailedCommits($result['output'], $separator);
    }

    /**
     * Parse commits from detailed format
     */
    private function parseDetailedCommits(string $output, string $separator): array
    {
        $output = trim($output);
        if ('' === $output || '0' === $output) {
            return [];
        }

        $lines   = explode("\n", $output);
        $commits = [];

        foreach ($lines as $line) {
            if (in_array(trim($line), ['', '0'], true)) {
                continue;
            }

            $parts = explode($separator, $line, 5);
            if (5 === count($parts)) {
                $email        = $parts[2] ?? '';
                $hash         = md5(strtolower(trim($email)));
                $gravatar_url = sprintf('https://www.gravatar.com/avatar/%s?s=64&d=identicon', $hash);

                $commits[] = [
                    'hash'         => $parts[0],
                    'author_name'  => $parts[1],
                    'author_email' => $email,
                    'date'         => $parts[3],
                    'message'      => $parts[4],
                    'gravatar_url' => $gravatar_url,
                ];
            }
        }

        return $commits;
    }

    /**
     * Parse commits from simple oneline format
     */
    private function parseSimpleCommits(string $output): array
    {
        $output = trim($output);
        if ('' === $output || '0' === $output) {
            return [];
        }

        $lines   = explode("\n", $output);
        $commits = [];

        foreach ($lines as $line) {
            if (in_array(trim($line), ['', '0'], true)) {
                continue;
            }

            $parts = explode(' ', $line, 2);
            if (count($parts) >= 2) {
                $commits[] = [
                    'hash'         => $parts[0],
                    'author_name'  => 'Unknown',
                    'author_email' => '',
                    'date'         => 'Unknown',
                    'message'      => $parts[1],
                    'gravatar_url' => 'https://www.gravatar.com/avatar/00000000000000000000000000000000?s=64&d=identicon',
                ];
            }
        }

        return $commits;
    }

    /**
     * Invalidate commits cache for a repository
     */
    private function invalidateCommitsCache(string $repoId): void
    {
        // Delete all possible commit cache variations for this repository without direct DB queries
        // Keep a registry of cache keys and delete those
        $registryKey = 'git_manager_commits_registry_' . $repoId;
        $keys        = get_option($registryKey, []);
        if (is_array($keys)) {
            foreach ($keys as $cacheKey) {
                delete_transient($cacheKey);
            }
        }

        delete_option($registryKey);
    }

    public function branch(): void
    {
        $this->ensureAllowed();
        check_ajax_referer('git_manager_action', 'nonce');
        $id   = $this->getRepositoryId();
        $repo = $this->repositoryManager->get($id);

        if (! $repo || ! $repo->path) {
            wp_send_json_error('Invalid data');
        }

        $branch = sanitize_text_field(wp_unslash($_POST['branch'] ?? ''));
        if (! $branch) {
            wp_send_json_error('Branch name required');
        }

        $result = GitCommandRunner::run($repo->path, 'checkout -b ' . escapeshellarg($branch));
        if ($result['success']) {
            wp_send_json_success(['message' => 'Branch created successfully']);
        } else {
            wp_send_json_error('Failed to create branch: ' . $result['output']);
        }
    }

    public function checkGitChanges(): void
    {
        $this->ensureAllowed();
        check_ajax_referer('git_manager_action', 'nonce');

        // Allow this check to run without a specific repository context
        $repoId = $this->getRepositoryId();

        if ('' === $repoId || '0' === $repoId) {
            wp_send_json_error('No repository specified');
        }

        $repo = $this->repositoryManager->get($repoId);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        $result     = GitCommandRunner::run($repo->path, 'status --porcelain');
        $hasChanges = !in_array(trim($result['output'] ?? ''), ['', '0'], true);

        wp_send_json_success(['hasChanges' => $hasChanges]);
    }

    public function fixPermission(): void
    {
        $this->ensureAllowed();
        check_ajax_referer('git_manager_action', 'nonce');
        $id   = $this->getRepositoryId();
        $repo = $this->repositoryManager->get($id);

        if ('' === $repoId || '0' === $repoId) {
            wp_send_json_error('No repository specified');
        }

        $repo = $this->repositoryManager->get($id);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Check if auto-fix is enabled
        if (! GitManager::is_auto_fix_enabled()) {
            wp_send_json_error([
                'message'           => 'Automatic fixes are disabled. Please enable them in the settings or contact your administrator.',
                'solution'          => 'Go to Repo Manager → Settings and enable "Automatic Fixes" option, or ask your administrator to enable it.',
                'auto_fix_disabled' => true,
            ]);
        }

        $result = SecureGitRunner::fixRepositoryPermissions($repo->path);

        if ($result['success']) {
            wp_send_json_success([
                'message' => 'Permissions fixed successfully',
                'details' => $result['details'],
            ]);
        } else {
            wp_send_json_error([
                'message'     => 'Permission fix failed. See details for more information.',
                'details'     => $result['details'] ?? [],
                'raw_output'  => $result['output'] ?? 'No output.',
            ]);
        }
    }

    public function fixSsh(): void
    {
        $this->ensureAllowed();
        check_ajax_referer('git_manager_action', 'nonce');
        $id   = $this->getRepositoryId();
        $repo = $this->repositoryManager->get($id);

        if ('' === $repoId || '0' === $repoId) {
            wp_send_json_error('No repository specified');
        }

        $repo = $this->repositoryManager->get($id);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Check if auto-fix is enabled
        if (! GitManager::is_auto_fix_enabled()) {
            wp_send_json_error([
                'message'           => 'Automatic fixes are disabled. Please enable them in the settings or contact your administrator.',
                'solution'          => 'Go to Repo Manager → Settings and enable "Automatic Fixes" option, or ask your administrator to enable it.',
                'auto_fix_disabled' => true,
            ]);
        }

        $result = SecureGitRunner::fixRepositoryPermissions($repo->path);

        if ($result['success']) {
            wp_send_json_success([
                'message' => 'Permissions fixed successfully',
                'details' => $result['details'],
            ]);
        } else {
            wp_send_json_error([
                'message'     => 'Permission fix failed. See details for more information.',
                'details'     => $result['details'] ?? [],
                'raw_output'  => $result['output'] ?? 'No output.',
            ]);
        }
    }

    public function saveRoles(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $roles = isset($_POST['roles']) && is_array($_POST['roles'])
            ? array_map('sanitize_text_field', (array) wp_unslash($_POST['roles']))
            : [];

        update_option('git_manager_allowed_roles', $roles);
        wp_send_json_success(['message' => 'Roles saved successfully']);
    }

    public function safeDirectory(): void
    {
        $this->ensureAllowed();
        check_ajax_referer('git_manager_action', 'nonce');
        $id   = $this->getRepositoryId();
        $repo = $this->repositoryManager->get($id);

        if ('' === $repoId || '0' === $repoId) {
            wp_send_json_error('No repository specified');
        }

        $repo = $this->repositoryManager->get($id);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Check if auto-fix is enabled
        if (! GitManager::is_auto_fix_enabled()) {
            wp_send_json_error([
                'message'           => 'Automatic fixes are disabled. Please enable them in the settings or contact your administrator.',
                'solution'          => 'Go to Repo Manager → Settings and enable "Automatic Fixes" option, or ask your administrator to enable it.',
                'auto_fix_disabled' => true,
            ]);
        }

        $result = GitCommandRunner::run($repo->path, 'config --local --add safe.directory ' . escapeshellarg($repo->path));
        if ($result['success']) {
            wp_send_json_success(['message' => 'Safe directory configured']);
        } else {
            wp_send_json_error('Failed to configure safe directory: ' . $result['output']);
        }
    }

    public function troubleshootStep(): void
    {
        $this->ensureAllowed();
        check_ajax_referer('git_manager_action', 'nonce');
        $step = sanitize_text_field(wp_unslash($_POST['step'] ?? ''));
        $id   = $this->getRepositoryId();

        if ('' === $repoId || '0' === $repoId) {
            wp_send_json_error('No repository specified');
        }

        $repo = $this->repositoryManager->get($id);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Perform step-specific troubleshooting
        $result = $this->performTroubleshootStep($step, $repo->path);
        wp_send_json_success($result);
    }

    private function performTroubleshootStep(string $step, string $repoPath): array
    {
        switch ($step) {
            case 'repo-path':
                return $this->checkRepoPath($repoPath);
            case 'git-binary':
                return $this->checkGitBinary();
            case 'git-directory':
                return $this->checkGitDirectory($repoPath);
            case 'safe-directory':
                return $this->checkSafeDirectory($repoPath);
            case 'permissions':
                return $this->checkPermissions($repoPath);
            case 'ssh-directory':
                return $this->checkSshDirectory();
            case 'ssh-keys':
                return $this->checkSshKeys();
            case 'host-keys':
                return $this->checkHostKeys();
            case 'git-config':
                return $this->checkGitConfig($repoPath);
            case 'remote-test':
                return $this->testRemoteConnection($repoPath);
            default:
                return [
                    'status'   => 'error',
                    'message'  => 'Unknown troubleshooting step: ' . $step,
                    'solution' => 'Please check the troubleshooting configuration',
                ];
        }
    }

    private function checkRepoPath(string $repoPath): array
    {
        if ('' === $repoPath || '0' === $repoPath) {
            return [
                'status'   => 'error',
                'message'  => 'Repository path is empty',
                'solution' => 'Please configure a valid repository path',
            ];
        }

        if (! is_dir($repoPath)) {
            return [
                'status'   => 'error',
                'message'  => 'Repository path does not exist: ' . $repoPath,
                'solution' => 'Please verify the repository path exists and is accessible',
            ];
        }

        if (! is_readable($repoPath)) {
            return [
                'status'   => 'error',
                'message'  => 'Repository path is not readable: ' . $repoPath,
                'solution' => 'Please check file permissions for the repository directory',
            ];
        }

        return [
            'status'  => 'success',
            'message' => 'Repository path is valid and accessible: ' . $repoPath,
            'details' => 'Path exists and is readable',
        ];
    }

    private function checkGitBinary(): array
    {
        try {
            // Check if git command is available in system PATH
            $versionRes = SecureGitRunner::gitVersion();
            $result     = $versionRes['output'] ?? '';

            if (null !== $result && false !== strpos($result, 'git version')) {
                $version = trim($result);

                return [
                    'status'   => 'success',
                    'message'  => 'Git is installed and accessible',
                    'details'  => $version,
                    'solution' => null,
                ];
            } else {
                // Try alternative methods to check Git
                $gitPaths = [
                    '/usr/bin/git',
                    '/usr/local/bin/git',
                    '/opt/homebrew/bin/git',
                    'C:\\Program Files\\Git\\bin\\git.exe',
                    'C:\\Program Files (x86)\\Git\\bin\\git.exe',
                ];

                foreach ($gitPaths as $gitPath) {
                    if (file_exists($gitPath)) {
                        return [
                            'status'   => 'warning',
                            'message'  => 'Git found but not in PATH: ' . $gitPath,
                            'details'  => 'Git is installed but may not be accessible from command line',
                            'solution' => 'Add Git to your system PATH or configure the full path in Repo Manager Settings',
                        ];
                    }
                }

                return [
                    'status'   => 'error',
                    'message'  => 'Git is not installed or not accessible',
                    'details'  => 'Git command not found in PATH or common installation directories',
                    'solution' => 'Please install Git from https://git-scm.com/ or ensure it is added to your system PATH',
                ];
            }
        } catch (Exception $exception) {
            return [
                'status'   => 'error',
                'message'  => 'Failed to check Git installation: ' . $exception->getMessage(),
                'details'  => $exception->getTraceAsString(),
                'solution' => 'Please check server configuration and try again',
            ];
        }
    }

    private function checkGitDirectory(string $repoPath): array
    {
        try {
            if ('' === $repoPath || '0' === $repoPath) {
                return [
                    'status'   => 'error',
                    'message'  => 'Repository path is empty',
                    'details'  => 'No repository path provided',
                    'solution' => 'Please configure a valid repository path',
                ];
            }

            if (! is_dir($repoPath)) {
                return [
                    'status'   => 'error',
                    'message'  => 'Repository path does not exist: ' . $repoPath,
                    'details'  => 'The specified directory does not exist on the filesystem',
                    'solution' => 'Please verify the repository path exists and is accessible',
                ];
            }

            if (! is_readable($repoPath)) {
                return [
                    'status'   => 'error',
                    'message'  => 'Repository path is not readable: ' . $repoPath,
                    'details'  => 'The directory exists but cannot be read by the web server',
                    'solution' => 'Please check file permissions for the repository directory',
                ];
            }

            // Check for .git directory
            $gitDir = $repoPath . '/.git';
            if (! is_dir($gitDir) && ! is_file($gitDir)) {
                return [
                    'status'   => 'error',
                    'message'  => 'Not a Git repository: ' . $repoPath,
                    'details'  => 'The .git directory is missing from the repository path',
                    'solution' => 'Please ensure this is a valid Git repository or run "git init" to initialize it',
                ];
            }

            if (! is_readable($gitDir)) {
                return [
                    'status'   => 'error',
                    'message'  => '.git directory is not readable: ' . $gitDir,
                    'details'  => 'The .git directory exists but cannot be read by the web server',
                    'solution' => 'Please check file permissions for the .git directory',
                ];
            }

            // Check for essential Git files
            $essentialFiles = ['HEAD', 'config', 'objects'];
            $missingFiles   = [];
            foreach ($essentialFiles as $file) {
                if (! file_exists($gitDir . '/' . $file)) {
                    $missingFiles[] = $file;
                }
            }

            if ([] !== $missingFiles) {
                return [
                    'status'   => 'warning',
                    'message'  => 'Git repository appears to be incomplete',
                    'details'  => 'Missing essential Git files: ' . implode(', ', $missingFiles),
                    'solution' => 'The repository may be corrupted. Try cloning it again or running "git init"',
                ];
            }

            return [
                'status'   => 'success',
                'message'  => 'Valid Git repository found: ' . $repoPath,
                'details'  => 'Repository contains all essential Git files and directories',
                'solution' => null,
            ];

        } catch (Exception $exception) {
            return [
                'status'   => 'error',
                'message'  => 'Failed to check Git directory: ' . $exception->getMessage(),
                'details'  => $exception->getTraceAsString(),
                'solution' => 'Please check server configuration and try again',
            ];
        }
    }

    private function checkSafeDirectory(string $repoPath): array
    {
        try {
            if ('' === $repoPath || '0' === $repoPath) {
                return [
                    'status'   => 'error',
                    'message'  => 'Repository path is empty',
                    'details'  => 'No repository path provided for safe directory check',
                    'solution' => 'Please configure a valid repository path',
                ];
            }

            // Get absolute path
            $absolutePath = realpath($repoPath);
            if (! $absolutePath) {
                return [
                    'status'   => 'error',
                    'message'  => 'Cannot resolve repository path: ' . $repoPath,
                    'details'  => 'The path could not be resolved to an absolute path',
                    'solution' => 'Please check the repository path and ensure it exists',
                ];
            }

            // Check current safe.directory configuration
            if (! GitManager::are_commands_enabled()) {
                return [
                    'status'   => 'warning',
                    'message'  => 'Command execution is disabled',
                    'details'  => 'Enable it in settings to check safe.directory automatically',
                    'solution' => 'Run manually: git config --global --get safe.directory',
                ];
            }

            $resultArr       = SecureGitRunner::runSystem('config --global --get safe.directory');
            $result          = $resultArr['output'] ?? '';
            $safeDirectories = array_filter(explode("\n", trim($result ?: '')));

            if (in_array($absolutePath, $safeDirectories)) {
                return [
                    'status'   => 'success',
                    'message'  => 'Repository is already in safe.directory list',
                    'details'  => 'Path: ' . $absolutePath,
                    'solution' => null,
                ];
            }

            // Check if auto-fix is enabled before trying to add to safe.directory
            if (! GitManager::is_auto_fix_enabled()) {
                return [
                    'status'   => 'warning',
                    'message'  => 'Repository not in safe.directory list (auto-fix disabled)',
                    'details'  => 'Path: ' . $absolutePath . ' needs to be added to Git safe directories',
                    'solution' => 'Enable automatic fixes in Repo Manager Settings, or run manually: git config --global --add safe.directory "' . $absolutePath . '"',
                ];
            }

            // Try to add to safe.directory
            if (! GitManager::are_commands_enabled()) {
                return [
                    'status'   => 'warning',
                    'message'  => 'Command execution is disabled',
                    'solution' => 'Please run manually: git config --global --add safe.directory "' . $absolutePath . '"',
                ];
            }

            $addResultArr = SecureGitRunner::runSystem('config --global --add safe.directory ' . escapeshellarg($absolutePath));
            $addResult    = $addResultArr['output'] ?? '';

            if (null === $addResult || false === strpos($addResult, 'error')) {
                return [
                    'status'   => 'success',
                    'message'  => 'Repository added to safe.directory list',
                    'details'  => 'Path: ' . $absolutePath . ' has been added to Git safe directories',
                    'solution' => null,
                ];
            } else {
                return [
                    'status'   => 'warning',
                    'message'  => 'Could not automatically add repository to safe.directory',
                    'details'  => 'Error: ' . $addResult,
                    'solution' => 'Please run manually: git config --global --add safe.directory "' . $absolutePath . '"',
                ];
            }

        } catch (Exception $exception) {
            return [
                'status'   => 'error',
                'message'  => 'Failed to check safe directory: ' . $exception->getMessage(),
                'details'  => $exception->getTraceAsString(),
                'solution' => 'Please check Git configuration manually',
            ];
        }
    }

    private function checkPermissions(string $repoPath): array
    {
        try {
            if ('' === $repoPath || '0' === $repoPath) {
                return [
                    'status'   => 'error',
                    'message'  => 'Repository path is empty',
                    'details'  => 'No repository path provided for permission check',
                    'solution' => 'Please configure a valid repository path',
                ];
            }

            if (! is_dir($repoPath)) {
                return [
                    'status'   => 'error',
                    'message'  => 'Repository path does not exist: ' . $repoPath,
                    'details'  => 'Cannot check permissions for non-existent directory',
                    'solution' => 'Please verify the repository path exists',
                ];
            }

            $issues   = [];
            $warnings = [];

            // Check repository directory permissions
            $repoPerms    = fileperms($repoPath);
            $repoPermsOct = substr(sprintf('%o', $repoPerms), -4);

            if (($repoPerms & 0x0004) === 0) {
                $issues[] = 'Repository directory is not readable by others';
            }

            if (($repoPerms & 0x0002) === 0) {
                $issues[] = 'Repository directory is not writable by others';
            }

            // Check .git directory permissions
            $gitDir = $repoPath . '/.git';
            if (is_dir($gitDir) || is_file($gitDir)) {
                $gitPerms    = fileperms($gitDir);
                $gitPermsOct = substr(sprintf('%o', $gitPerms), -4);

                if (($gitPerms & 0x0004) === 0) {
                    $issues[] = '.git directory is not readable by others';
                }

                if (($gitPerms & 0x0002) === 0) {
                    $issues[] = '.git directory is not writable by others';
                }
            }

            // Check web server user
            $webServerUser = function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : 'unknown';
            $repoOwner     = function_exists('posix_getpwuid') ? posix_getpwuid(fileowner($repoPath))['name'] : 'unknown';

            if ($webServerUser !== $repoOwner && 'unknown' !== $repoOwner) {
                $warnings[] = sprintf("Repository owned by '%s' but web server runs as '%s'", $repoOwner, $webServerUser);
            }

            // Check specific files
            $criticalFiles = [
                $repoPath . '/.git/config',
                $repoPath . '/.git/HEAD',
                $repoPath . '/.git/index',
            ];

            foreach ($criticalFiles as $file) {
                if (file_exists($file)) {
                    if (! is_readable($file)) {
                        $issues[] = 'Critical file not readable: ' . basename($file);
                    }

                    // Use WP_Filesystem instead of is_writable
                    global $wp_filesystem;
                    if (empty($wp_filesystem)) {
                        require_once(ABSPATH . '/wp-admin/includes/file.php');
                        WP_Filesystem();
                    }

                    if ($wp_filesystem && ! $wp_filesystem->is_writable($file)) {
                        $warnings[] = 'Critical file not writable: ' . basename($file);
                    } elseif (! $wp_filesystem) {
                        $warnings[] = 'WordPress filesystem not available for permission check';
                    }
                }
            }

            if ([] !== $issues) {
                return [
                    'status'   => 'error',
                    'message'  => 'Permission issues found',
                    'details'  => implode("\n", $issues),
                    'solution' => 'Please fix file permissions. Recommended: chmod -R 755 "' . $repoPath . '"',
                ];
            }

            if ([] !== $warnings) {
                return [
                    'status'   => 'warning',
                    'message'  => 'Permission warnings found',
                    'details'  => implode("\n", $warnings),
                    'solution' => 'Consider adjusting file permissions for better compatibility',
                ];
            }

            return [
                'status'   => 'success',
                'message'  => 'File permissions are acceptable',
                'details'  => 'Repository and .git directory have proper read/write permissions',
                'solution' => null,
            ];

        } catch (Exception $exception) {
            return [
                'status'   => 'error',
                'message'  => 'Failed to check permissions: ' . $exception->getMessage(),
                'details'  => $exception->getTraceAsString(),
                'solution' => 'Please check file permissions manually',
            ];
        }
    }

    private function checkSshDirectory(): array
    {
        $home   = getenv('HOME') ?: getenv('USERPROFILE') ?: sys_get_temp_dir();
        $sshDir = $home . '/.ssh';

        if (! is_dir($sshDir)) {
            return [
                'status'   => 'warning',
                'message'  => 'SSH directory does not exist',
                'solution' => 'Create SSH directory: mkdir -p ~/.ssh && chmod 700 ~/.ssh',
            ];
        }

        if (! is_readable($sshDir)) {
            return [
                'status'   => 'error',
                'message'  => 'SSH directory is not readable',
                'solution' => 'Fix SSH directory permissions: chmod 700 ~/.ssh',
            ];
        }

        return [
            'status'  => 'success',
            'message' => 'SSH directory exists and is accessible',
            'details' => 'SSH directory: ' . $sshDir,
        ];
    }

    private function checkSshKeys(): array
    {
        $home   = getenv('HOME') ?: getenv('USERPROFILE') ?: sys_get_temp_dir();
        $sshDir = $home . '/.ssh';

        if (! is_dir($sshDir)) {
            return [
                'status'   => 'warning',
                'message'  => 'SSH directory does not exist',
                'solution' => 'Create SSH directory first: mkdir -p ~/.ssh && chmod 700 ~/.ssh',
            ];
        }

        $privateKeys = glob($sshDir . '/id_*');
        glob($sshDir . '/id_*.pub');

        if ([] === $privateKeys || false === $privateKeys) {
            return [
                'status'   => 'warning',
                'message'  => 'No SSH private keys found',
                'solution' => 'Generate SSH key: ssh-keygen -t rsa -b 4096 -C "your_email@example.com"',
            ];
        }

        $keyInfo = [];
        foreach ($privateKeys as $key) {
            $perms     = fileperms($key);
            $keyInfo[] = ($perms & 0x0177) !== 0 ? basename($key) . ' (permissions too open)' : basename($key) . ' (OK)';
        }

        return [
            'status'  => 'success',
            'message' => 'SSH keys found: ' . count($privateKeys),
            'details' => 'Keys: ' . implode(', ', $keyInfo),
        ];
    }

    private function checkHostKeys(): array
    {
        $home       = getenv('HOME') ?: getenv('USERPROFILE') ?: sys_get_temp_dir();
        $knownHosts = $home . '/.ssh/known_hosts';

        if (! file_exists($knownHosts)) {
            return [
                'status'   => 'warning',
                'message'  => 'Known hosts file does not exist',
                'solution' => 'Connect to your Git host first to add host keys',
            ];
        }

        $content = file_get_contents($knownHosts);
        if (false === $content) {
            return [
                'status'   => 'error',
                'message'  => 'Could not read known_hosts file',
                'solution' => 'Check file permissions for ~/.ssh/known_hosts',
            ];
        }

        $hosts = ['github.com', 'gitlab.com', 'bitbucket.org'];
        $found = [];

        foreach ($hosts as $host) {
            if (false !== strpos($content, $host)) {
                $found[] = $host;
            }
        }

        if ([] === $found) {
            return [
                'status'   => 'warning',
                'message'  => 'No common Git hosts found in known_hosts',
                'solution' => 'Connect to your Git host first: ssh -T git@github.com',
            ];
        }

        return [
            'status'  => 'success',
            'message' => 'Host keys found for: ' . implode(', ', $found),
            'details' => 'Known hosts file contains entries for common Git hosts',
        ];
    }

    private function checkGitConfig(string $repoPath): array
    {
        // Check if this is a Git repository first
        if (! \WPGitManager\Service\SecureGitRunner::isGitRepositoryPath($repoPath)) {
            return [
                'status'   => 'error',
                'message'  => 'Not a Git repository',
                'solution' => 'Please initialize this directory as a Git repository first',
            ];
        }

        if (! GitManager::are_commands_enabled()) {
            return [
                'status'   => 'warning',
                'message'  => 'Command execution is disabled',
                'solution' => 'Enable command execution in plugin settings to check Git config automatically',
            ];
        }

        $userNameRes  = SecureGitRunner::runInDirectory($repoPath, 'config user.name');
        $userEmailRes = SecureGitRunner::runInDirectory($repoPath, 'config user.email');
        $userName     = $userNameRes['output'] ?? '';
        $userEmail    = $userEmailRes['output'] ?? '';

        $issues = [];
        if (null === $userName || in_array(trim($userName), ['', '0'], true)) {
            $issues[] = 'User name not configured';
        }

        if (null === $userEmail || in_array(trim($userEmail), ['', '0'], true)) {
            $issues[] = 'User email not configured';
        }

        if ([] === $issues) {
            return [
                'status'  => 'success',
                'message' => 'Git user configuration is complete',
                'details' => 'Name: ' . trim($userName) . ', Email: ' . trim($userEmail),
            ];
        } else {
            return [
                'status'   => 'warning',
                'message'  => 'Git configuration issues: ' . implode(', ', $issues),
                'solution' => 'Configure Git user: git config user.name "Your Name" && git config user.email "your_email@example.com"',
            ];
        }
    }

    private function testRemoteConnection(string $repoPath): array
    {
        // Check if this is a Git repository first
        if (! \WPGitManager\Service\SecureGitRunner::isGitRepositoryPath($repoPath)) {
            return [
                'status'   => 'error',
                'message'  => 'Not a Git repository',
                'solution' => 'Please initialize this directory as a Git repository first',
            ];
        }

        if (! GitManager::are_commands_enabled()) {
            return [
                'status'   => 'warning',
                'message'  => 'Command execution is disabled',
                'solution' => 'Enable command execution in plugin settings to check remotes automatically',
            ];
        }

        $remoteRes = SecureGitRunner::runInDirectory($repoPath, 'remote -v');
        $result    = $remoteRes['output'] ?? '';
        if (null === $result || in_array(trim($result), ['', '0'], true)) {
            return [
                'status'   => 'error',
                'message'  => 'No remote repositories configured',
                'solution' => 'Add a remote repository: git remote add origin <repository-url>',
            ];
        }

        $remotes   = explode("\n", trim($result));
        $remoteUrl = '';
        foreach ($remotes as $remote) {
            if (false !== strpos($remote, 'origin')) {
                $parts = explode("\t", $remote);
                if (count($parts) >= 2) {
                    $remoteUrl = trim($parts[1]);
                    break;
                }
            }
        }

        if ('' === $remoteUrl || '0' === $remoteUrl) {
            return [
                'status'   => 'error',
                'message'  => 'No origin remote found',
                'solution' => 'Add origin remote: git remote add origin <repository-url>',
            ];
        }

        // Test connection (this might take a while)
        if (! GitManager::are_commands_enabled()) {
            return [
                'status'   => 'warning',
                'message'  => 'Command execution is disabled',
                'solution' => 'Enable command execution in plugin settings to test remote connection automatically',
            ];
        }

        $testRes    = SecureGitRunner::runInDirectory($repoPath, 'ls-remote --exit-code origin');
        $testResult = $testRes['output'] ?? '';
        if ($testRes['success'] && null !== $testResult && false === strpos($testResult, 'error')) {
            return [
                'status'  => 'success',
                'message' => 'Remote connection successful',
                'details' => 'Origin remote: ' . $remoteUrl,
            ];
        } else {
            return [
                'status'   => 'error',
                'message'  => 'Remote connection failed',
                'solution' => 'Check network connectivity and SSH/HTTPS configuration for: ' . $remoteUrl,
            ];
        }
    }

    public function troubleshoot(): void
    {
        $this->ensureAllowed();
        check_ajax_referer('git_manager_action', 'nonce');
        // No specific repo context needed for this high-level troubleshooter
    }

    /**
     * Generate Gravatar URL for author
     */
    private function getGravatarUrl($author): array
    {
        $authorName  = '';
        $authorEmail = '';

        // Extract email from author string (format: "Name <email@example.com>")
        if (preg_match('/<(.+?)>/', $author, $matches)) {
            $authorEmail = trim($matches[1]);
            $authorName  = trim(str_replace($matches[0], '', $author));
        } else {
            // If no email found, try to extract from common patterns
            // Some git configs might use "Name email@example.com" format
            $parts = explode(' ', trim($author));
            foreach ($parts as $part) {
                if (filter_var($part, FILTER_VALIDATE_EMAIL)) {
                    $authorEmail = $part;
                    $authorName  = trim(str_replace($part, '', $author));
                    break;
                }
            }

            // If still no email found, use the whole string as name
            if ('' === $authorEmail || '0' === $authorEmail) {
                $authorName = trim($author);
            }
        }

        // Clean up author name (remove extra spaces)
        $authorName = preg_replace('/\s+/', ' ', $authorName);

        $gravatarUrl = '';
        if ('' !== $authorEmail && '0' !== $authorEmail && '0' !== $authorEmail) {
            // Generate Gravatar URL with size 40px and default avatar
            $hash        = md5(strtolower(trim($authorEmail)));
            $gravatarUrl = sprintf('https://www.gravatar.com/avatar/%s?s=40&d=mp&r=g', $hash);
        }

        return [
            'name'         => $authorName,
            'email'        => $authorEmail,
            'gravatar_url' => $gravatarUrl,
            'has_avatar'   => '' !== $gravatarUrl && '0' !== $gravatarUrl,
        ];
    }

    /**
     * Re-clone a repository that has a missing folder
     */
    public function reClone(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        $repoId = $this->getRepositoryId();
        if ('' === $repoId || '0' === $repoId) {
            wp_send_json_error('No repository specified');
        }

        $repo = $this->repositoryManager->get($repoId);
        if (!$repo instanceof Repository) {
            wp_send_json_error('Repository not found');
        }

        // Check if repository folder is missing
        if (is_dir($repo->path)) {
            wp_send_json_error('Repository folder already exists');
        }

        // Check if we have a remote URL
        if (empty($repo->remoteUrl)) {
            wp_send_json_error('No remote URL configured for this repository. Please add a remote URL first.');
        }

        // Create parent directory if it doesn't exist
        $parentDir = dirname($repo->path);
        if (!is_dir($parentDir) && ! wp_mkdir_p($parentDir)) {
            wp_send_json_error('Failed to create parent directory: ' . $parentDir);
        }

        // Check if git is available
        if (! GitManager::are_commands_enabled()) {
            wp_send_json_error('Command execution is disabled');
        }

        $gitVersionRes = SecureGitRunner::gitVersion();
        $gitVersion    = $gitVersionRes['output'] ?? '';
        if (! $gitVersion || false === strpos($gitVersion, 'git version')) {
            wp_send_json_error('Git is not available on the system. Please install Git first.');
        }

        // Clone the repository
        $cloneRes = SecureGitRunner::cloneRepository($repo->remoteUrl, $repo->path);
        $output   = $cloneRes['output'] ?? '';
        $exitCode = $cloneRes['exit_code'] ?? 1;

        // Check for common error patterns in the output
        $errorPatterns = [
            'fatal:',
            'error:',
            'Permission denied',
            'Could not resolve host',
            'Connection refused',
            'Authentication failed',
            'Repository not found',
        ];

        $hasError = false;
        foreach ($errorPatterns as $pattern) {
            if (false !== stripos($output, $pattern)) {
                $hasError = true;
                break;
            }
        }

        if (0 !== $exitCode || $hasError) {
            wp_send_json_error('Failed to clone repository: ' . $output);
        }

        // Verify the clone was successful
        if (! \WPGitManager\Service\SecureGitRunner::isGitRepositoryPath($repo->path)) {
            wp_send_json_error('Repository was cloned but .git directory is missing. The clone may have failed.');
        }

        wp_send_json_success([
            'message' => 'Repository cloned successfully',
            'path'    => $repo->path,
        ]);
    }

    /**
     * Get bulk repository status and latest commit
     */
    public function getBulkRepoStatus(): void
    {
        $this->ensureAllowed();

        check_ajax_referer('git_manager_action', 'nonce');

        // Optional hint from clients (e.g., floating widget) to prefer cached results
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $useCacheParam = sanitize_text_field(wp_unslash($_POST['use_cache'] ?? ''));
        $useCache      = ('1' === $useCacheParam || 'true' === strtolower($useCacheParam));

        $repos = $this->repositoryManager->all();
        if (empty($repos)) {
            wp_send_json_error('No repositories found');
        }

        $results = [];
        foreach ($repos as $repo) {
            if (!$repo || empty($repo->path)) {
                continue;
            }

            // Per-repository cache to avoid expensive git calls on frequent polls
            $bulkCacheKey = 'git_manager_cache_bulk_repo_status_' . $repo->id;
            $cachedBulk   = get_transient($bulkCacheKey);
            if (false !== $cachedBulk && $useCache) {
                $results[$repo->id] = $cachedBulk;
                continue;
            }

            // Check if repository directory exists with improved path resolution
            $resolvedPath = $this->resolveRepositoryPath($repo->path);
            if (!is_dir($resolvedPath)) {
                $results[$repo->id] = [
                    'status'        => null,
                    'status_error'  => 'Repository directory does not exist: ' . $repo->path,
                    'latest_commit' => null,
                    'commit_error'  => 'Repository directory does not exist: ' . $repo->path,
                    'behind'        => 0,
                    'ahead'         => 0,
                    'hasChanges'    => false,
                    'currentBranch' => null,
                ];
                continue;
            }

            // Check if .git directory exists
            if (! \WPGitManager\Service\SecureGitRunner::isGitRepositoryPath($resolvedPath)) {
                $results[$repo->id] = [
                    'status'        => null,
                    'status_error'  => 'Not a valid Git repository: .git directory not found',
                    'latest_commit' => null,
                    'commit_error'  => 'Not a valid Git repository: .git directory not found',
                    'behind'        => 0,
                    'ahead'         => 0,
                    'hasChanges'    => false,
                    'currentBranch' => null,
                ];
                continue;
            }

            // Ensure we have the latest remote state (heavily throttled)
            // $throttleKey = 'git_manager_last_fetch_' . $repo->id;
            // if (false === get_transient($throttleKey)) {
            //     // Perform background fetch far less frequently to reduce load
            //     SecureGitRunner::runInDirectory($repo->path, 'fetch --all --prune', ['low_priority' => true]);
            //     // Align with very infrequent UI polling; 8 hours
            //     set_transient($throttleKey, time(), 8 * HOUR_IN_SECONDS);
            // }

            // Get branch information
            $branchResult  = SecureGitRunner::runInDirectory($resolvedPath, 'rev-parse --abbrev-ref HEAD');
            $currentBranch = trim($branchResult['output'] ?? '');

            if (!$branchResult['success'] || ('' === $currentBranch || '0' === $currentBranch)) {
                $results[$repo->id] = [
                    'status'        => null,
                    'status_error'  => 'Failed to determine current branch',
                    'latest_commit' => null,
                    'commit_error'  => 'Failed to determine current branch',
                    'behind'        => 0,
                    'ahead'         => 0,
                    'hasChanges'    => false,
                    'currentBranch' => null,
                ];
                continue;
            }

            // Get detailed status with branch information
            $statusResult = SecureGitRunner::runInDirectory($resolvedPath, 'status --porcelain --branch');
            $commitResult = SecureGitRunner::runInDirectory($resolvedPath, 'log -1 --pretty=format:%h|%s|%an|%ar');

            if (!$statusResult['success']) {
                $errorMessage = 'Failed to get repository status';
                if (!empty($statusResult['output'])) {
                    $errorMessage .= ': ' . trim($statusResult['output']);
                }

                $results[$repo->id] = [
                    'status'        => null,
                    'status_error'  => $errorMessage,
                    'latest_commit' => $commitResult['success'] ? $commitResult['output'] : null,
                    'commit_error'  => $commitResult['success'] ? null : $commitResult['output'],
                    'behind'        => 0,
                    'ahead'         => 0,
                    'hasChanges'    => false,
                    'currentBranch' => $currentBranch,
                ];
                continue;
            }

            // Parse the status output to extract behind/ahead information
            $statusOutput = $statusResult['output'] ?? '';
            $lines        = explode("\n", trim($statusOutput));

            $behind     = 0;
            $ahead      = 0;
            $hasChanges = false;

            foreach ($lines as $line) {
                $line = trim($line);

                // Check for branch status line (starts with ##)
                if (0 === strpos($line, '##')) {
                    // Extract behind/ahead information
                    if (preg_match('/behind (\d+)/', $line, $matches)) {
                        $behind = (int) $matches[1];
                    }

                    if (preg_match('/ahead (\d+)/', $line, $matches)) {
                        $ahead = (int) $matches[1];
                    }
                } elseif ('' !== $line && '0' !== $line) {
                    // Any non-empty line that doesn't start with ## indicates changes
                    $hasChanges = true;
                }
            }

            $results[$repo->id] = [
                'status'        => $statusResult['success'] ? $statusResult['output'] : null,
                'status_error'  => $statusResult['success'] ? null : $statusResult['output'],
                'latest_commit' => $commitResult['success'] ? $commitResult['output'] : null,
                'commit_error'  => $commitResult['success'] ? null : $commitResult['output'],
                'behind'        => $behind,
                'ahead'         => $ahead,
                'hasChanges'    => $hasChanges,
                'currentBranch' => $currentBranch,
                'rawOutput'     => $statusOutput,
            ];

            // Cache computed result briefly to serve polling clients quickly
            set_transient($bulkCacheKey, $results[$repo->id], 30);
        }

        wp_send_json_success($results);
    }

    /**
     * Resolve repository path with improved path handling
     *
     * @param string $path The repository path to resolve
     * @return string The resolved absolute path
     */
    private function resolveRepositoryPath(string $path): string
    {
        // If path is already absolute, return as is
        if (path_is_absolute($path)) {
            return $path;
        }

        // Handle WordPress relative paths
        $wpRelativePaths = ['/wp-content', '/wp-admin', '/wp-includes', '/wp-json'];
        $isWpRelative = false;
        foreach ($wpRelativePaths as $wpPath) {
            if (0 === strpos($path, $wpPath)) {
                $isWpRelative = true;
                break;
            }
        }

        if ($isWpRelative) {
            $resolvedPath = ABSPATH . ltrim($path, '/');
        } else {
            // Try to resolve relative path from WordPress root
            $resolvedPath = ABSPATH . ltrim($path, '/');
        }

        // Normalize path separators
        $resolvedPath = str_replace(['\\', '/'], DIRECTORY_SEPARATOR, $resolvedPath);

        // Remove any double separators
        $resolvedPath = preg_replace('/' . preg_quote(DIRECTORY_SEPARATOR, '/') . '+/', DIRECTORY_SEPARATOR, $resolvedPath);

        // Resolve any '..' and '.' in the path
        $resolvedPath = realpath($resolvedPath) ?: $resolvedPath;

        // Log path resolution for debugging (only in development)
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log("Repo Manager: Resolving path '{$path}' to '{$resolvedPath}' (exists: " . (is_dir($resolvedPath) ? 'yes' : 'no') . ")");
        }

        return $resolvedPath;
    }
}
