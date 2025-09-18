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
        $this->id        = $data['id'] ?? wp_generate_uuid4();
        $this->name      = $data['name'] ?? 'Repository';
        $this->path      = rtrim($data['path'] ?? '', '\\/');
        $this->remoteUrl = $data['remoteUrl'] ?? null;
        $this->authType  = $data['authType'] ?? 'ssh';
        $this->meta      = is_array($data['meta'] ?? null) ? $data['meta'] : [];
    }

    public function getDisplayPath(): string
    {
        $path         = wp_normalize_path($this->path);
        $real_wp_root = rtrim(wp_normalize_path(realpath(ABSPATH)), '/');

        if (empty($_SERVER['DOCUMENT_ROOT'])) {
            return $path;
        }
        $doc_root = rtrim(wp_normalize_path($_SERVER['DOCUMENT_ROOT']), '/');

        if (basename($real_wp_root) === basename($doc_root) && str_starts_with($path, $real_wp_root)) {
            return $doc_root . substr($path, strlen($real_wp_root));
        }

        return $path;
    }

    public function toArray(): array
    {
        return [
            'id'           => $this->id,
            'name'         => $this->name,
            'path'         => $this->getDisplayPath(),
            'remoteUrl'    => $this->remoteUrl,
            'authType'     => $this->authType,
            'meta'         => $this->meta,
            'activeBranch' => $this->activeBranch,
        ];
    }
}
