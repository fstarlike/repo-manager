<?php

namespace WPGitManager\Model;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Value object representing a Git repository managed by the Plugin.
 */
class Repository
{
    public string $id;

    public string $name;

    public string $path;

    public ?string $remoteUrl;

    public string $authType;

    public array $meta;

    public ?string $activeBranch = null;

    public function __construct(array $data)
    {
        echo '<pre>';
        var_dump($data);
        echo '</pre>';
        die;
        $this->id        = $data['id'] ?? wp_generate_uuid4();
        $this->name      = $data['name'] ?? 'Repository';
        $this->path      = rtrim($data['path'] ?? '', '\\/');
        $this->remoteUrl = $data['remoteUrl'] ?? null;
        $this->authType  = $data['authType'] ?? 'ssh';
        $this->meta      = is_array($data['meta'] ?? null) ? $data['meta'] : [];
    }

    public function getDisplayPath(): string
    {
        $path = wp_normalize_path($this->path);

        $realAbspath   = rtrim(wp_normalize_path((string) realpath(ABSPATH)), '/');
        $logicalAbspath = rtrim(wp_normalize_path(ABSPATH), '/');

        $realWpContent = rtrim(wp_normalize_path((string) realpath(WP_CONTENT_DIR)), '/');
        $logicalWpContent = rtrim(wp_normalize_path(WP_CONTENT_DIR), '/');

        // Prefer mapping by ABSPATH if possible
        if ($realAbspath && str_starts_with($path, $realAbspath)) {
            return $logicalAbspath . substr($path, strlen($realAbspath));
        }

        // Fallback: map by WP_CONTENT_DIR if ABSPATH didn’t match
        if ($realWpContent && str_starts_with($path, $realWpContent)) {
            return $logicalWpContent . substr($path, strlen($realWpContent));
        }

        // As a last resort, try DOCUMENT_ROOT mapping if it looks equivalent
        $docRoot = isset($_SERVER['DOCUMENT_ROOT']) ? rtrim(wp_normalize_path($_SERVER['DOCUMENT_ROOT']), '/') : '';
        if ($docRoot && $realAbspath && basename($docRoot) === basename($realAbspath) && str_starts_with($path, $realAbspath)) {
            return $docRoot . substr($path, strlen($realAbspath));
        }

        return $path;
    }

    public function toArray(): array
    {
        return [
            'id'           => $this->id,
            'name'         => $this->name,
            'path'         => $this->getDisplayPath(),
            'storedPath'   => wp_normalize_path($this->path),
            'remoteUrl'    => $this->remoteUrl,
            'authType'     => $this->authType,
            'meta'         => $this->meta,
            'activeBranch' => $this->activeBranch,
        ];
    }
}
