<?php

namespace WPGitManager\View\Admin;

use WPGitManager\Admin\GitManager;
use WPGitManager\Infrastructure\RTLSupport;
use WPGitManager\Service\SystemStatus;
use WPGitManager\View\Components\Header;

if (! defined('ABSPATH')) {
    exit;
}

class Status
{
    private Header $header;

    public function __construct()
    {
        $this->header = new Header();
    }

    public function render(): void
    {
        $this->enqueueAssets();

        $rtlAttributes = RTLSupport::getRTLWrapperAttributes();
        $checks        = SystemStatus::gather();

        ?>
        <div class="wrap" <?php echo esc_attr($rtlAttributes); ?>>
            <?php $this->header->render(); ?>

            <div class="repo-manager-status-dashboard">
                <div class="git-repo-content">
                    <!-- Status Page Header -->
                    <div class="repo-details-header">
                        <h2><?php echo esc_html__('System Status', 'repo-manager'); ?></h2>
                        <div class="repo-details-actions">
                            <a class="git-action-btn git-secondary-btn" href="<?php echo esc_url(admin_url('admin.php?page=repo-manager')); ?>">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
                                    <path d="M19 12H5"/>
                                    <path d="M12 19l-7-7 7-7"/>
                                </svg>
                                <?php echo esc_html__('Back to Dashboard', 'repo-manager'); ?>
                            </a>
                            <a class="git-action-btn" href="<?php echo esc_url(add_query_arg('gm_status_refresh', '1')); ?>">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
                                    <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/>
                                    <path d="M21 3v5h-5"/>
                                    <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/>
                                    <path d="M8 16H3v5"/>
                                </svg>
                                <?php echo esc_html__('Run Checks Again', 'repo-manager'); ?>
                            </a>
                            <a class="git-action-btn git-secondary-btn" href="<?php echo esc_url(admin_url('admin.php?page=repo-manager-settings')); ?>">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
                                    <circle cx="12" cy="12" r="3"/>
                                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1 1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                                </svg>
                                <?php echo esc_html__('Open Settings', 'repo-manager'); ?>
                            </a>
                        </div>
                    </div>

                    <!-- Summary Cards -->
                    <?php $this->renderSummary($checks['summary']); ?>

                    <!-- Status Groups -->
                    <div class="repo-overview-grid">
                        <?php $this->renderGroup(__('Environment', 'repo-manager'), $checks['environment'], 'cpu'); ?>
                        <?php $this->renderGroup(__('WordPress', 'repo-manager'), $checks['wordpress'], 'wp'); ?>
                        <?php $this->renderGroup(__('Git', 'repo-manager'), $checks['git'], 'git'); ?>
                    </div>

                    <!-- Guides Section -->
                    <?php $this->renderGuides(); ?>
                </div>
            </div>

            <?php $this->renderSSHInstallModal(); ?>
        </div>


        <script>
        document.addEventListener('DOMContentLoaded', function() {
            const modal = document.getElementById('ssh-install-modal');

            // Using event delegation for the open button
            document.body.addEventListener('click', function(e) {
                if (e.target.matches('[data-action="ssh-git-install"]')) {
                    e.preventDefault();
                    modal.classList.add('is-visible');
                }
            });

            // Handle modal close via button, overlay click, or escape key
            if (modal) {
                modal.addEventListener('click', function(e) {
                    if (e.target.id === 'ssh-install-modal' || e.target.id === 'ssh-modal-close' || e.target.closest('#ssh-modal-close')) {
                        modal.classList.remove('is-visible');
                    }
                });

                document.addEventListener('keydown', function(e) {
                    if (e.key === "Escape" && modal.classList.contains('is-visible')) {
                        modal.classList.remove('is-visible');
                    }
                });
            }


            // Handle custom file upload
            const fileUploadButton = document.querySelector('.file-upload-button');
            const fileUploadInput = document.getElementById('ssh-key-file');
            const fileUploadName = document.querySelector('.file-upload-name');

            if (fileUploadButton && fileUploadInput && fileUploadName) {
                fileUploadButton.addEventListener('click', () => {
                    fileUploadInput.click();
                });

                fileUploadInput.addEventListener('change', () => {
                    if (fileUploadInput.files.length > 0) {
                        fileUploadName.textContent = fileUploadInput.files[0].name;
                        fileUploadName.style.fontStyle = 'normal';
                    } else {
                        fileUploadName.textContent = WPGitManagerGlobal.translations.noFileSelected;
                        fileUploadName.style.fontStyle = 'italic';
                    }
                });
            }

            // Handle SSH connection test
            const testBtn = document.getElementById('test-ssh-btn');
            if (testBtn) {
                testBtn.addEventListener('click', function() {
                    const host = document.getElementById('ssh-host').value;
                    const port = document.getElementById('ssh-port').value;
                    const username = document.getElementById('ssh-username').value;
                    const password = document.getElementById('ssh-password').value;
                    const keyFile = document.getElementById('ssh-key-file').files[0];

                    if (!host || !username) {
                        alert('Host and username are required');
                        return;
                    }

                    testBtn.disabled = true;
                    testBtn.textContent = WPGitManagerGlobal.translations.testingSSHConnection;

                    const formData = new FormData();
                    formData.append('action', 'git_manager_test_ssh');
                    formData.append('nonce', WPGitManagerGlobal.nonce);
                    formData.append('host', host);
                    formData.append('port', port);
                    formData.append('username', username);
                    formData.append('password', password);
                    if (keyFile) {
                        formData.append('ssh_key_file', keyFile);
                    }

                    fetch(WPGitManagerGlobal.ajaxurl, {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert(WPGitManagerGlobal.translations.sshConnectionSuccess);
                            document.getElementById('install-git-btn').disabled = false;
                        } else {
                            alert(WPGitManagerGlobal.translations.sshConnectionFailed + ': ' + data.data);
                        }
                    })
                    .catch(error => {
                        alert('Error: ' + error.message);
                    })
                    .finally(() => {
                        testBtn.disabled = false;
                        testBtn.textContent = WPGitManagerGlobal.translations.sshConnectionTest;
                    });
                });
            }

            // Handle Git installation
            const installBtn = document.getElementById('install-git-btn');
            if (installBtn) {
                installBtn.addEventListener('click', function() {
                    const host = document.getElementById('ssh-host').value;
                    const port = document.getElementById('ssh-port').value;
                    const username = document.getElementById('ssh-username').value;
                    const password = document.getElementById('ssh-password').value;
                    const keyFile = document.getElementById('ssh-key-file').files[0];

                    if (!host || !username) {
                        alert('Host and username are required');
                        return;
                    }

                    if (!confirm('This will install Git on the remote server. Continue?')) {
                        return;
                    }

                    installBtn.disabled = true;
                    installBtn.textContent = WPGitManagerGlobal.translations.installingGit;

                    const formData = new FormData();
                    formData.append('action', 'git_manager_install_git_ssh');
                    formData.append('nonce', WPGitManagerGlobal.nonce);
                    formData.append('host', host);
                    formData.append('port', port);
                    formData.append('username', username);
                    formData.append('password', password);
                    if (keyFile) {
                        formData.append('ssh_key_file', keyFile);
                    }

                    fetch(WPGitManagerGlobal.ajaxurl, {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert(WPGitManagerGlobal.translations.gitInstallationSuccess);
                            location.reload();
                        } else {
                            alert(WPGitManagerGlobal.translations.gitInstallationFailed + ': ' + data.data);
                        }
                    })
                    .catch(error => {
                        alert('Error: ' + error.message);
                    })
                    .finally(() => {
                        installBtn.disabled = false;
                        installBtn.textContent = WPGitManagerGlobal.translations.installGitViaSSH;
                    });
                });
            }
        });
        </script>
        <?php
    }

    private function enqueueAssets(): void
    {
        // Enqueue status-specific CSS
        wp_enqueue_style('repo-manager-status', GIT_MANAGER_URL . 'dist/css/status.css', ['repo-manager-admin'], GIT_MANAGER_VERSION);

        // CSS/JS already handled globally in GitManager::enqueue_assets
        if (RTLSupport::isRTL() && wp_script_is('repo-manager-rtl-support', 'enqueued')) {
            wp_localize_script('repo-manager-rtl-support', 'gitManagerRTL', RTLSupport::getRTLSettings());
        }
    }

    private function renderSummary(array $summary): void
    {
        $total   = (int) ($summary['pass'] + $summary['warn'] + $summary['fail']);
        $okPct   = $total > 0 ? round(($summary['pass'] / $total) * 100) : 0;
        ?>
        <div class="repo-overview-grid">
            <!-- Overall Health Card -->
            <div class="overview-card">
                <div class="overview-card-header">
                    <div class="overview-card-title-wrap">
                        <span class="overview-card-icon" aria-hidden="true">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z"/><line x1="12" x2="12" y1="16" y2="12"/><line x1="12" x2="12.01" y1="8" y2="8"/></svg>
                        </span>
                        <h3 class="overview-card-title"><?php echo esc_html__('Overall Health', 'repo-manager'); ?></h3>
                    </div>
                    <span class="count-badge"><?php echo esc_html((string) $okPct); ?>%</span>
                </div>
                <div class="overview-card-body">
                    <p class="value">
                        <?php echo esc_html(sprintf(__('%s%% of checks passed', 'repo-manager'), (string) $okPct)); ?>
                    </p>
                </div>
            </div>

            <!-- Passed Checks Card -->
            <div class="overview-card">
                <div class="overview-card-header">
                    <div class="overview-card-title-wrap">
                        <span class="overview-card-icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                                <polyline points="22,4 12,14.01 9,11.01"/>
                            </svg>
                        </span>
                        <h3 class="overview-card-title"><?php echo esc_html__('Passed', 'repo-manager'); ?></h3>
                    </div>
                    <span class="count-badge"><?php echo esc_html((string) $summary['pass']); ?></span>
                </div>
                <div class="overview-card-body">
                    <p class="value"><?php echo esc_html__('All systems operational', 'repo-manager'); ?></p>
                </div>
            </div>

            <!-- Warnings Card -->
            <div class="overview-card">
                <div class="overview-card-header">
                    <div class="overview-card-title-wrap">
                        <span class="overview-card-icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                                <line x1="12" y1="9" x2="12" y2="13"/>
                                <line x1="12" y1="17" x2="12.01" y2="17"/>
                            </svg>
                        </span>
                        <h3 class="overview-card-title"><?php echo esc_html__('Warnings', 'repo-manager'); ?></h3>
                    </div>
                    <span class="count-badge"><?php echo esc_html((string) $summary['warn']); ?></span>
                </div>
                <div class="overview-card-body">
                    <p class="value"><?php echo esc_html__('Minor issues detected', 'repo-manager'); ?></p>
                </div>
            </div>

            <!-- Failed Checks Card -->
            <div class="overview-card">
                <div class="overview-card-header">
                    <div class="overview-card-title-wrap">
                        <span class="overview-card-icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"/>
                                <line x1="15" y1="9" x2="9" y2="15"/>
                                <line x1="9" y1="9" x2="15" y2="15"/>
                            </svg>
                        </span>
                        <h3 class="overview-card-title"><?php echo esc_html__('Failed', 'repo-manager'); ?></h3>
                    </div>
                    <span class="count-badge"><?php echo esc_html((string) $summary['fail']); ?></span>
                </div>
                <div class="overview-card-body">
                    <p class="value"><?php echo esc_html__('Critical issues found', 'repo-manager'); ?></p>
                </div>
            </div>
        </div>
        <?php
    }

    private function renderGroup(string $title, array $items, string $icon = ''): void
    {
        ?>
        <div class="overview-card">
            <div class="overview-card-header">
                <div class="overview-card-title-wrap">
                    <?php if ('git' === $icon) { ?>
                        <span class="overview-card-icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M7 7l10 10"/>
                                <path d="M6 18V6h12"/>
                            </svg>
                        </span>
                    <?php } elseif ('wp' === $icon) { ?>
                        <span class="overview-card-icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"/>
                                <path d="M8 12h8"/>
                                <path d="M12 8v8"/>
                            </svg>
                        </span>
                    <?php } else { ?>
                        <span class="overview-card-icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                                <line x1="8" y1="21" x2="16" y2="21"/>
                                <line x1="12" y1="17" x2="12" y2="21"/>
                            </svg>
                        </span>
                    <?php } ?>
                    <h3 class="overview-card-title"><?php echo esc_html($title); ?></h3>
                </div>
            </div>
            <div class="overview-card-body">
                <div class="status-items">
                    <?php foreach ($items as $item) { $this->renderItem($item); } ?>
                </div>
            </div>
        </div>
        <?php
    }

    private function renderItem(array $item): void
    {
        $status = $item['status'];
        $statusClass = ('pass' === $status) ? 'status-pass' : (('warn' === $status) ? 'status-warn' : (('fail' === $status) ? 'status-fail' : 'status-neutral'));
        ?>
        <div class="status-item <?php echo esc_attr($statusClass); ?>" data-status="<?php echo esc_attr($status); ?>">
            <div class="status-item-header">
                <div class="status-indicator">
                    <?php if ('pass' === $status) { ?>
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                            <polyline points="22,4 12,14.01 9,11.01"/>
                        </svg>
                    <?php } elseif ('warn' === $status) { ?>
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                    <?php } elseif ('fail' === $status) { ?>
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="15" y1="9" x2="9" y2="15"/>
                            <line x1="9" y1="9" x2="15" y2="15"/>
                        </svg>
                    <?php } else { ?>
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="12" y1="8" x2="12" y2="12"/>
                            <line x1="12" y1="16" x2="12.01" y2="16"/>
                        </svg>
                    <?php } ?>
                </div>
                <div class="status-content">
                    <div class="status-label"><?php echo esc_html($item['label']); ?></div>
                    <?php if (!empty($item['value'])) { ?>
                        <div class="status-value"><?php echo esc_html($item['value']); ?></div>
                    <?php } ?>
                </div>
            </div>
            <?php if (!empty($item['message'])) { ?>
                <div class="status-message">
                    <p><?php echo esc_html($item['message']); ?></p>
                    <?php if (!empty($item['action'])) { $this->renderAction($item['action']); } ?>
                </div>
            <?php } ?>
        </div>
        <?php
    }

    private function renderAction(array $action): void
    {
        $label = $action['label'] ?? '';
        $url   = $action['url'] ?? '';
        $dataAction = $action['data_action'] ?? '';

        if ('' === $label || ('' === $url && '' === $dataAction)) {
            return;
        }
        ?>
        <div class="status-action">
            <?php if ($dataAction) { ?>
                <button class="git-action-btn <?php echo !empty($action['secondary']) ? 'git-secondary-btn' : ''; ?>" data-action="<?php echo esc_attr($dataAction); ?>">
                    <?php echo esc_html($label); ?>
                </button>
            <?php } else { ?>
                <a class="git-action-btn <?php echo !empty($action['secondary']) ? 'git-secondary-btn' : ''; ?>" href="<?php echo esc_url($url); ?>" target="<?php echo !empty($action['external']) ? '_blank' : '_self'; ?>" rel="noopener noreferrer">
                    <?php echo esc_html($label); ?>
                </a>
            <?php } ?>
        </div>
        <?php
    }

    private function renderGuides(): void
    {
        $commandsEnabled = GitManager::are_commands_enabled();
        $gitInstalled   = $commandsEnabled && SystemStatus::gitAvailable();
        $isWindows      = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
        $gitDownloadUrl = $isWindows ? 'https://git-scm.com/download/win' : 'https://git-scm.com/downloads';

        ?>
        <div class="overview-card">
            <div class="overview-card-header">
                <div class="overview-card-title-wrap">
                    <span class="overview-card-icon" aria-hidden="true">
                        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="10"/>
                            <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                    </span>
                    <h3 class="overview-card-title"><?php echo esc_html__('Guides & Help', 'repo-manager'); ?></h3>
                </div>
            </div>
            <div class="overview-card-body">
                <div class="guides-grid">
                    <?php if (!$commandsEnabled) { ?>
                    <div class="guide-item">
                        <div class="guide-icon">
                            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="3"/>
                                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1 1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                            </svg>
                        </div>
                        <div class="guide-content">
                            <h4><?php echo esc_html__('Enable Command Execution', 'repo-manager'); ?></h4>
                            <p><?php echo esc_html__('To run Git checks and operations, enable command execution in plugin settings. Only enable this on trusted servers.', 'repo-manager'); ?></p>
                            <a class="git-action-btn" href="<?php echo esc_url(admin_url('admin.php?page=repo-manager-settings')); ?>"><?php echo esc_html__('Open Settings', 'repo-manager'); ?></a>
                        </div>
                    </div>
                    <?php } ?>

                    <div class="guide-item">
                        <div class="guide-icon">
                            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M7 7l10 10"/>
                                <path d="M6 18V6h12"/>
                            </svg>
                        </div>
                        <div class="guide-content">
                            <h4><?php echo esc_html__('Install Git', 'repo-manager'); ?></h4>
                            <p><?php echo esc_html__('If Git is not installed on the server, install it following the official instructions for your OS.', 'repo-manager'); ?></p>
                            <a class="git-action-btn git-secondary-btn" href="<?php echo esc_url($gitDownloadUrl); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html__('Download Git', 'repo-manager'); ?></a>
                        </div>
                    </div>

                    <div class="guide-item">
                        <div class="guide-icon">
                            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>
                                <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
                            </svg>
                        </div>
                        <div class="guide-content">
                            <h4><?php echo esc_html__('Configure Git User', 'repo-manager'); ?></h4>
                            <p><?php echo esc_html__('Set your global user.name and user.email so commits are attributed correctly.', 'repo-manager'); ?></p>
                            <div class="code-block">
                                <code>git config --global user.name "Your Name"</code>
                                <code>git config --global user.email "you@example.com"</code>
                            </div>
                        </div>
                    </div>

                    <?php if (!$gitInstalled) { ?>
                    <div class="guide-item">
                        <div class="guide-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z"/><line x1="12" x2="12" y1="16" y2="12"/><line x1="12" x2="12.01" y1="8" y2="8"/></svg>
                        </div>
                        <div class="guide-content">
                            <h4><?php echo esc_html__('SSH Auto-Installation', 'repo-manager'); ?></h4>
                            <p><?php echo esc_html__('If you have SSH access to your server, you can attempt to install Git automatically.', 'repo-manager'); ?></p>
                            <button class="git-action-btn" data-action="ssh-git-install"><?php echo esc_html__('Install via SSH', 'repo-manager'); ?></button>
                        </div>
                    </div>
                    <?php } ?>
                </div>
            </div>
        </div>
        <?php
    }

    private function renderSSHInstallModal(): void
    {
        ?>
        <div id="ssh-install-modal" class="git-modal-overlay" data-modal-id="ssh-install">
            <div class="git-modal" role="dialog" aria-modal="true" aria-labelledby="ssh-modal-title">
                <div class="git-modal-header">
                    <h3 id="ssh-modal-title"><?php echo esc_html__('Install Git via SSH', 'repo-manager'); ?></h3>
                    <button type="button" class="git-modal-close" id="ssh-modal-close" aria-label="<?php echo esc_attr__('Close', 'repo-manager'); ?>">&times;</button>
                </div>
                <div class="git-modal-body">
                    <p><?php echo esc_html__('Connect to a remote server via SSH to install Git automatically.', 'repo-manager'); ?></p>

                    <div class="form-group">
                        <label for="ssh-host"><?php echo esc_html__('SSH Host', 'repo-manager'); ?></label>
                        <input type="text" id="ssh-host" class="form-control" placeholder="example.com" required>
                        <div class="form-help"><?php echo esc_html__('The hostname or IP address of the remote server', 'repo-manager'); ?></div>
                    </div>

                    <div class="form-group">
                        <label for="ssh-port"><?php echo esc_html__('SSH Port', 'repo-manager'); ?></label>
                        <input type="number" id="ssh-port" class="form-control" placeholder="22">
                        <div class="form-help"><?php echo esc_html__('The SSH port of the remote server (leave blank for default)', 'repo-manager'); ?></div>
                    </div>

                    <div class="form-group">
                        <label for="ssh-username"><?php echo esc_html__('SSH Username', 'repo-manager'); ?></label>
                        <input type="text" id="ssh-username" class="form-control" placeholder="root" required>
                        <div class="form-help"><?php echo esc_html__('Username for SSH authentication', 'repo-manager'); ?></div>
                    </div>

                    <div class="form-group">
                        <label for="ssh-password"><?php echo esc_html__('SSH Password', 'repo-manager'); ?></label>
                        <input type="password" id="ssh-password" class="form-control" placeholder="Password">
                        <div class="form-help"><?php echo esc_html__('Password for SSH authentication (optional if using SSH key)', 'repo-manager'); ?></div>
                    </div>

                    <div class="form-group">
                        <label for="ssh-key-file"><?php echo esc_html__('SSH Private Key', 'repo-manager'); ?></label>
                        <div class="file-upload-wrapper">
                            <input type="file" id="ssh-key-file" class="file-upload-input" accept=".pem,.key,application/x-x509-ca-cert">
                            <button type="button" class="git-action-btn git-secondary-btn file-upload-button"><?php echo esc_html__('Select Key File', 'repo-manager'); ?></button>
                            <span class="file-upload-name"><?php echo esc_html__('No file selected', 'repo-manager'); ?></span>
                        </div>
                        <div class="form-help"><?php echo esc_html__('Upload your SSH private key. The key will not be stored on the server.', 'repo-manager'); ?></div>
                    </div>
                </div>
                <div class="git-modal-footer">
                    <button type="button" class="git-action-btn git-secondary-btn" id="test-ssh-btn">
                        <?php echo esc_html__('Test SSH Connection', 'repo-manager'); ?>
                    </button>
                    <button type="button" class="git-action-btn" id="install-git-btn" disabled>
                        <?php echo esc_html__('Install Git via SSH', 'repo-manager'); ?>
                    </button>
                </div>
            </div>
        </div>
        <?php
    }
}
