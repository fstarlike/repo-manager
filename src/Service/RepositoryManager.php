<?php

namespace WPGitManager\Service;

use WPGitManager\Model\Repository;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Manages persistence and retrieval of repositories.
 */
class RepositoryManager
{
    private const OPTION_KEY = 'git_manager_repositories';

    private const ACTIVE_KEY = 'git_manager_active_repo';

    /** @var Repository[] */
    private array $cache = [];

    private bool $loaded = false;

    private static ?self $instance = null;

    public static function instance(): self
    {
        return self::$instance ??= new self();
    }

    private function __construct()
    {
    }

    private function ensureLoaded(): void
    {
        if ($this->loaded) {
            return;
        }

        $this->load();
        $this->loaded = true;
    }

    private function load(): void
    {
        $stored = get_option(self::OPTION_KEY, []);
        if (! is_array($stored)) {
            $stored = [];
        }

        $this->cache = [];
        $unique_paths = [];

        $plugin_dir = plugin_dir_path( __FILE__ );
        $wp_root = dirname( $plugin_dir, 2 );

        echo '<pre>';
        var_dump(ABSPATH, $wp_root);
        echo '</pre>';
        die;
        foreach ($stored as $item) {
            if (is_array($item)) {
                $repo = new Repository($item);
                if ('' !== $repo->path && '0' !== $repo->path) {
                    // Prevent adding duplicates based on path
                    if (isset($unique_paths[$repo->path])) {
                        continue;
                    }
                    $this->cache[$repo->id] = $repo;
                    $unique_paths[$repo->path] = true;
                }
            }
        }
    }

    private function persist(): void
    {
        $out = [];
        foreach ($this->cache as $repo) {
            $out[] = $repo->toArray();
        }

        update_option(self::OPTION_KEY, $out, false);
    }

    /** @return Repository[] */
    public function all(): array
    {
        $this->ensureLoaded();
        return array_values($this->cache);
    }

    public function get(string $id): ?Repository
    {
        $this->ensureLoaded();
        return $this->cache[$id] ?? null;
    }

    public function getActiveId(): ?string
    {
        $this->ensureLoaded();
        $id = get_option(self::ACTIVE_KEY);

        return $id && isset($this->cache[$id]) ? $id : null;
    }

    public function setActive(string $id): bool
    {
        $this->ensureLoaded();
        if (! isset($this->cache[$id])) {
            return false;
        }

        update_option(self::ACTIVE_KEY, $id, false);

        return true;
    }

    public function add(array $data): Repository
    {
        $this->ensureLoaded();
        $repo                   = new Repository($data);
        $this->cache[$repo->id] = $repo;
        $this->persist();

        return $repo;
    }

    public function update(string $id, array $data): ?Repository
    {
        $this->ensureLoaded();
        $repo = $this->get($id);
        if (!$repo instanceof Repository) {
            return null;
        }

        foreach (['name', 'path', 'remoteUrl', 'authType', 'meta'] as $k) {
            if (array_key_exists($k, $data)) {
                $repo->$k = ('path' === $k) ? rtrim((string) $data[$k], '\\/') : $data[$k];
            }
        }

        $this->persist();

        return $repo;
    }

    public function delete(string $id): bool
    {
        $this->ensureLoaded();
        if (! isset($this->cache[$id])) {
            return false;
        }

        unset($this->cache[$id]);
        $this->persist();
        $active = $this->getActiveId();
        if ($active === $id) {
            delete_option(self::ACTIVE_KEY);
        }

        return true;
    }

    /**
     * Resolve a potentially relative path to a full, canonical path.
     *
     * @param string $path The path to resolve.
     * @return string The resolved absolute path.
     */
    public function resolvePath(string $path): string
    {
        // Trim whitespace and quotes, then normalize slashes
        $path = wp_normalize_path(trim($path, " \t\n\r\0\x0B\"'"));

        // If path is already an absolute path, just return it
        if (path_is_absolute($path)) {
            return $path;
        }

        // It's a relative path, so resolve it relative to the WordPress root
        return wp_normalize_path(ABSPATH . ltrim($path, '/'));
    }

    /** Basic path security: ensure requested path stays inside ABSPATH unless user has manage_options */
    public function validatePath(string $path): bool
    {
        $absolutePath = $path;

        if (0 === strpos($path, '/wp-content') || 0 === strpos($path, '/wp-admin') || 0 === strpos($path, '/wp-includes')) {
            $absolutePath = ABSPATH . ltrim($path, '/');

        } elseif (! path_is_absolute($path)) {
            $absolutePath = ABSPATH . $path;

        } else {

        }

        $real = realpath($absolutePath);

        if ($real) {
            $real = rtrim($real, '\\/');
            $root = rtrim(ABSPATH, '\\/');

            if (current_user_can('manage_options')) {
                return true;
            }

            return 0 === strpos($real, $root);
        } else {
            $parent = dirname($absolutePath);
            $real   = realpath($parent);

            if (! $real) {

                return false;
            }

            $real = rtrim($real, '\\/');
            $root = rtrim(ABSPATH, '\\/');

            if (current_user_can('manage_options')) {
                return true;
            }

            return 0 === strpos($real, $root);
        }
    }

    /**
     * Clean up legacy repositories and options
     */
    public function cleanupLegacyData(): void
    {
        $this->ensureLoaded();
        delete_option('git_manager_repo_path');
        delete_option('git_manager_repos');

        $legacyIds = [];
        foreach ($this->cache as $id => $repo) {
            if (false !== strpos($repo->name, 'Legacy')) {
                $legacyIds[] = $id;
            }
        }

        foreach ($legacyIds as $id) {
            $this->delete($id);
        }

        $activeId = $this->getActiveId();
        if ($activeId && ! isset($this->cache[$activeId])) {
            delete_option(self::ACTIVE_KEY);
        }
    }
}
