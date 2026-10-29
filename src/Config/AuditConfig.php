<?php
/**
 * Composer-Audit-ZeroTrust: Configuration Manager
 * Part of Composer-Audit-ZeroTrust by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

namespace ComposerZeroTrust\Config;

class AuditConfig
{
    private array $allowedPackages = [];
    private array $ignorePaths = [];
    private float $entropyThreshold = 5.6;
    private int $maxTyposquatDistance = 2;
    private int $maxFindingsFail = 1;

    public static function loadFromPath(string $projectPath): self
    {
        $config = new self();
        $configFile = rtrim($projectPath, '/') . '/composer-zerotrust.json';

        if (file_exists($configFile)) {
            $data = json_decode((string)file_get_contents($configFile), true);
            if (is_array($data)) {
                if (isset($data['whitelist']) && is_array($data['whitelist'])) {
                    $config->allowedPackages = $data['whitelist'];
                }
                if (isset($data['ignore_paths']) && is_array($data['ignore_paths'])) {
                    $config->ignorePaths = $data['ignore_paths'];
                }
                if (isset($data['entropy_threshold'])) {
                    $config->entropyThreshold = (float)$data['entropy_threshold'];
                }
                if (isset($data['max_typosquat_distance'])) {
                    $config->maxTyposquatDistance = (int)$data['max_typosquat_distance'];
                }
            }
        }

        return $config;
    }

    public function isPackageWhitelisted(string $packageName): bool
    {
        return in_array($packageName, $this->allowedPackages, true);
    }

    public function isPathIgnored(string $filePath): bool
    {
        foreach ($this->ignorePaths as $ignore) {
            if (strpos($filePath, $ignore) !== false) {
                return true;
            }
        }
        return false;
    }

    public function getEntropyThreshold(): float
    {
        return $this->entropyThreshold;
    }

    public function getMaxTyposquatDistance(): int
    {
        return $this->maxTyposquatDistance;
    }
}
