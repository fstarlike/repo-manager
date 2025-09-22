<?php

namespace WPGitManager\Service;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Centralized configuration management for Repo Manager
 */
class Configuration
{
    private const OPTION_KEY = 'git_manager_configuration';

    /**
     * Default configuration values
     */
    private const DEFAULTS = [
        // Security settings
        'security' => [
            'max_execution_time'      => 30,
            'max_output_size'         => 1048576, // 1MB
            'rate_limit_window'       => 60, // 1 minute
            'rate_limit_max_requests' => 30,
            'allowed_commands'        => [
                'status', 'log', 'branch', 'checkout', 'pull', 'push', 'fetch',
                'clone', 'config', 'remote', 'add', 'commit', 'diff', 'show',
                'ls-remote', 'rev-parse', 'symbolic-ref', 'describe', 'tag',
                'merge', 'rebase', 'stash', 'reset', 'clean',
            ],
        ],

        // Performance settings
        'performance' => [
            'cache_ttl'            => 300, // 5 minutes
            'polling_interval'     => 5000, // 5 seconds
            'max_repositories'     => 50,
            'max_commits_display'  => 100,
            'max_branches_display' => 50,
            'enable_compression'   => true,
            'lazy_loading'         => true,
        ],

        // UI/UX settings
        'ui' => [
            'theme'                          => 'auto', // auto, light, dark
            'floating_widget_enabled'        => true,
            'floating_notifications_enabled' => true,
            'animations_enabled'             => true,
            'keyboard_shortcuts_enabled'     => true,
            'auto_refresh_enabled'           => true,
            'show_file_changes'              => true,
            'show_commit_hashes'             => true,
        ],

        // Git settings
        'git' => [
            'default_branch'      => 'main',
            'auto_fetch_enabled'  => false,
            'auto_pull_enabled'   => false,
            'conflict_resolution' => 'manual', // manual, auto
            'merge_strategy'      => 'merge', // merge, rebase
            'push_strategy'       => 'safe', // safe, force, force-with-lease
            'clone_depth'         => 0, // 0 = full clone
            'timeout'             => 30,
        ],

        // Logging settings
        'logging' => [
            'enabled'             => true,
            'level'               => 'info', // debug, info, warning, error
            'max_log_entries'     => 1000,
            'log_retention_days'  => 30,
            'audit_enabled'       => true,
            'performance_logging' => false,
        ],

        // Integration settings
        'integration' => [
            'webhook_enabled'   => false,
            'webhook_secret'    => '',
            'api_enabled'       => false,
            'api_rate_limit'    => 100, // requests per hour
            'external_services' => [
                'github'    => ['enabled' => false, 'token' => ''],
                'gitlab'    => ['enabled' => false, 'token' => ''],
                'bitbucket' => ['enabled' => false, 'token' => ''],
            ],
        ],
    ];

    private static ?array $config = null;

    /**
     * Get configuration value
     */
    public static function get(string $key, $default = null)
    {
        if (null === self::$config) {
            self::load();
        }

        $keys  = explode('.', $key);
        $value = self::$config;

        foreach ($keys as $k) {
            if (!is_array($value) || !array_key_exists($k, $value)) {
                return $default;
            }

            $value = $value[$k];
        }

        return $value;
    }

    /**
     * Set configuration value
     */
    public static function set(string $key, $value): void
    {
        if (null === self::$config) {
            self::load();
        }

        $keys   = explode('.', $key);
        $config = &self::$config;

        foreach ($keys as $k) {
            if (!is_array($config)) {
                $config = [];
            }

            if (!array_key_exists($k, $config)) {
                $config[$k] = [];
            }

            $config = &$config[$k];
        }

        $config = $value;
        self::save();
    }

    /**
     * Get all configuration
     */
    public static function all(): array
    {
        if (null === self::$config) {
            self::load();
        }

        return self::$config;
    }

    /**
     * Reset configuration to defaults
     */
    public static function reset(): void
    {
        self::$config = self::DEFAULTS;
        self::save();
    }

    /**
     * Validate configuration
     */
    public static function validate(array $config): array
    {
        $errors = [];

        // Validate security settings
        if (isset($config['security'])) {
            $security = $config['security'];

            if (isset($security['max_execution_time']) && (!is_numeric($security['max_execution_time']) || $security['max_execution_time'] < 1 || $security['max_execution_time'] > 300)) {
                $errors[] = 'Max execution time must be between 1 and 300 seconds';
            }

            if (isset($security['max_output_size']) && (!is_numeric($security['max_output_size']) || $security['max_output_size'] < 1024 || $security['max_output_size'] > 10485760)) {
                $errors[] = 'Max output size must be between 1KB and 10MB';
            }

            if (isset($security['rate_limit_max_requests']) && (!is_numeric($security['rate_limit_max_requests']) || $security['rate_limit_max_requests'] < 1 || $security['rate_limit_max_requests'] > 200)) {
                $errors[] = 'Rate limit max requests must be between 1 and 200';
            }
        }

        // Validate performance settings
        if (isset($config['performance'])) {
            $performance = $config['performance'];

            if (isset($performance['cache_ttl']) && (!is_numeric($performance['cache_ttl']) || $performance['cache_ttl'] < 60 || $performance['cache_ttl'] > 3600)) {
                $errors[] = 'Cache TTL must be between 60 and 3600 seconds';
            }

            if (isset($performance['max_repositories']) && (!is_numeric($performance['max_repositories']) || $performance['max_repositories'] < 1 || $performance['max_repositories'] > 1000)) {
                $errors[] = 'Max repositories must be between 1 and 1000';
            }
        }

        // Validate UI settings
        if (isset($config['ui'])) {
            $ui = $config['ui'];

            if (isset($ui['theme']) && !in_array($ui['theme'], ['auto', 'light', 'dark'])) {
                $errors[] = 'Theme must be auto, light, or dark';
            }
        }

        // Validate Git settings
        if (isset($config['git'])) {
            $git = $config['git'];

            if (isset($git['conflict_resolution']) && !in_array($git['conflict_resolution'], ['manual', 'auto'])) {
                $errors[] = 'Conflict resolution must be manual or auto';
            }

            if (isset($git['merge_strategy']) && !in_array($git['merge_strategy'], ['merge', 'rebase'])) {
                $errors[] = 'Merge strategy must be merge or rebase';
            }

            if (isset($git['push_strategy']) && !in_array($git['push_strategy'], ['safe', 'force', 'force-with-lease'])) {
                $errors[] = 'Push strategy must be safe, force, or force-with-lease';
            }
        }

        return $errors;
    }

    /**
     * Load configuration from database
     */
    private static function load(): void
    {
        $stored = get_option(self::OPTION_KEY, []);

        if (!is_array($stored)) {
            $stored = [];
        }

        // Merge with defaults
        self::$config = self::mergeConfig(self::DEFAULTS, $stored);
    }

    /**
     * Save configuration to database
     */
    private static function save(): void
    {
        if (null === self::$config) {
            return;
        }

        update_option(self::OPTION_KEY, self::$config, false);
    }

    /**
     * Recursively merge configuration arrays
     */
    private static function mergeConfig(array $defaults, array $stored): array
    {
        foreach ($stored as $key => $value) {
            if (is_array($value) && isset($defaults[$key]) && is_array($defaults[$key])) {
                $defaults[$key] = self::mergeConfig($defaults[$key], $value);
            } else {
                $defaults[$key] = $value;
            }
        }

        return $defaults;
    }

    /**
     * Get configuration schema for UI
     */
    public static function getSchema(): array
    {
        return [
            'security' => [
                'title'       => 'Security Settings',
                'description' => 'Configure security-related settings',
                'fields'      => [
                    'max_execution_time' => [
                        'type'        => 'number',
                        'label'       => 'Max Execution Time (seconds)',
                        'description' => 'Maximum time allowed for Git command execution',
                        'min'         => 1,
                        'max'         => 300,
                        'default'     => 30,
                    ],
                    'max_output_size' => [
                        'type'        => 'number',
                        'label'       => 'Max Output Size (bytes)',
                        'description' => 'Maximum size of command output',
                        'min'         => 1024,
                        'max'         => 10485760,
                        'default'     => 1048576,
                    ],
                    'rate_limit_max_requests' => [
                        'type'        => 'number',
                        'label'       => 'Rate Limit Max Requests',
                        'description' => 'Maximum requests per minute per user',
                        'min'         => 1,
                        'max'         => 100,
                        'default'     => 10,
                    ],
                ],
            ],
            'performance' => [
                'title'       => 'Performance Settings',
                'description' => 'Configure performance-related settings',
                'fields'      => [
                    'cache_ttl' => [
                        'type'        => 'number',
                        'label'       => 'Cache TTL (seconds)',
                        'description' => 'How long to cache repository data',
                        'min'         => 60,
                        'max'         => 3600,
                        'default'     => 300,
                    ],
                    'polling_interval' => [
                        'type'        => 'number',
                        'label'       => 'Polling Interval (milliseconds)',
                        'description' => 'How often to check for repository updates',
                        'min'         => 1000,
                        'max'         => 30000,
                        'default'     => 5000,
                    ],
                    'max_repositories' => [
                        'type'        => 'number',
                        'label'       => 'Max Repositories',
                        'description' => 'Maximum number of repositories to manage',
                        'min'         => 1,
                        'max'         => 1000,
                        'default'     => 50,
                    ],
                ],
            ],
            'ui' => [
                'title'       => 'UI/UX Settings',
                'description' => 'Configure user interface settings',
                'fields'      => [
                    'theme' => [
                        'type'        => 'select',
                        'label'       => 'Theme',
                        'description' => 'Choose the interface theme',
                        'options'     => [
                            'auto'  => 'Auto (System)',
                            'light' => 'Light',
                            'dark'  => 'Dark',
                        ],
                        'default' => 'auto',
                    ],
                    'floating_widget_enabled' => [
                        'type'        => 'checkbox',
                        'label'       => 'Enable Floating Widget',
                        'description' => 'Show floating widget on all admin pages',
                        'default'     => true,
                    ],
                    'animations_enabled' => [
                        'type'        => 'checkbox',
                        'label'       => 'Enable Animations',
                        'description' => 'Enable UI animations and transitions',
                        'default'     => true,
                    ],
                ],
            ],
        ];
    }

    /**
     * Export configuration
     */
    public static function export(): array
    {
        return [
            'version'       => GIT_MANAGER_VERSION,
            'timestamp'     => current_time('mysql'),
            'configuration' => self::all(),
        ];
    }

    /**
     * Import configuration
     */
    public static function import(array $data): array
    {
        $errors = [];

        if (!isset($data['configuration']) || !is_array($data['configuration'])) {
            $errors[] = 'Invalid configuration data';
            return $errors;
        }

        $validationErrors = self::validate($data['configuration']);
        if ([] !== $validationErrors) {
            return $validationErrors;
        }

        self::$config = self::mergeConfig(self::DEFAULTS, $data['configuration']);
        self::save();

        return $errors;
    }
}
