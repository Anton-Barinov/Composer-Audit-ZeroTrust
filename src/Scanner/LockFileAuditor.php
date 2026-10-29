<?php
/**
 * Composer-Audit-ZeroTrust: Composer.lock & Script Integrity Auditor
 * Part of Composer-Audit-ZeroTrust by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

namespace ComposerZeroTrust\Scanner;

use ComposerZeroTrust\Config\AuditConfig;

class LockFileAuditor
{
    private AuditConfig $config;

    public function __construct(AuditConfig $config)
    {
        $this->config = $config;
    }

    /**
     * Audit composer.lock and composer.json for supply-chain risks
     * 
     * @param string $lockFilePath Path to composer.lock
     * @return array<int, array<string, mixed>>
     */
    public function audit(string $lockFilePath): array
    {
        $findings = [];
        if (!file_exists($lockFilePath)) {
            return [
                [
                    'type'       => 'MISSING_LOCK_FILE',
                    'severity'   => 'HIGH',
                    'package'    => 'project',
                    'detail'     => 'No composer.lock file found! Without a lock file, builds are vulnerable to non-deterministic dependency hijacking.',
                    'risk_score' => 20,
                ]
            ];
        }

        $data = json_decode((string)file_get_contents($lockFilePath), true);
        if (!is_array($data)) {
            return [
                [
                    'type'       => 'CORRUPTED_LOCK_FILE',
                    'severity'   => 'CRITICAL',
                    'package'    => 'project',
                    'detail'     => 'composer.lock contains invalid JSON syntax.',
                    'risk_score' => 50,
                ]
            ];
        }

        $packages = is_array($data['packages'] ?? null) ? $data['packages'] : [];
        $packagesDev = is_array($data['packages-dev'] ?? null) ? $data['packages-dev'] : [];
        $allPackages = array_merge($packages, $packagesDev);

        foreach ($allPackages as $pkg) {
            if (!is_array($pkg)) {
                continue;
            }
            $name = $pkg['name'] ?? 'unknown';
            if ($this->config->isPackageWhitelisted($name)) {
                continue;
            }

            // 1. Insecure / Plain HTTP Download URLs (MitM Risk)
            $distUrl = $pkg['dist']['url'] ?? '';
            $sourceUrl = $pkg['source']['url'] ?? '';

            if (strpos($distUrl, 'http://') === 0 || strpos($sourceUrl, 'http://') === 0) {
                $findings[] = [
                    'type'       => 'INSECURE_HTTP_DIST_URL',
                    'severity'   => 'HIGH',
                    'package'    => $name,
                    'detail'     => "Package downloads via unencrypted HTTP ({$distUrl}). Vulnerable to in-flight tampering & MitM code injection.",
                    'risk_score' => 30,
                ];
            }

            // 2. Raw IP address in download source
            if (preg_match('/https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/', $distUrl . ' ' . $sourceUrl)) {
                $findings[] = [
                    'type'       => 'RAW_IP_DOWNLOAD_SOURCE',
                    'severity'   => 'CRITICAL',
                    'package'    => $name,
                    'detail'     => "Package source points directly to a raw IP address instead of a trusted domain or code repository.",
                    'risk_score' => 45,
                ];
            }

            // 3. Post-install / Lifecycle Script Execution (Supply-Chain Remote Execution)
            if (isset($pkg['scripts']) && is_array($pkg['scripts'])) {
                foreach ($pkg['scripts'] as $event => $cmdList) {
                    $cmds = is_array($cmdList) ? $cmdList : [$cmdList];
                    foreach ($cmds as $cmd) {
                        if (!is_string($cmd)) continue;
                        if (preg_match('/(?:curl|wget|bash|sh|powershell|cmd\.exe|nc|socat)\b/i', $cmd)) {
                            $findings[] = [
                                'type'       => 'DANGEROUS_LIFECYCLE_SCRIPT',
                                'severity'   => 'CRITICAL',
                                'package'    => $name,
                                'detail'     => "Dependency executes suspicious shell/network command during '{$event}': '{$cmd}'.",
                                'risk_score' => 50,
                            ];
                        }
                    }
                }
            }

            // 4. Missing Checksums / Tamper Verification
            if (isset($pkg['dist']['type']) && $pkg['dist']['type'] === 'zip') {
                $shasum = $pkg['dist']['shasum'] ?? '';
                if ($shasum === '' && empty($pkg['source']['reference'])) {
                    $findings[] = [
                        'type'       => 'MISSING_PACKAGE_INTEGRITY_HASH',
                        'severity'   => 'MEDIUM',
                        'package'    => $name,
                        'detail'     => "Package archive has neither a distribution checksum nor a Git reference commit for integrity verification.",
                        'risk_score' => 15,
                    ];
                }
            }

            // 5. Untrusted / Suspicious TLD repository sources
            if (preg_match('/\.(?:top|xyz|click|tk|pw|work|rest)\b/i', $distUrl . ' ' . $sourceUrl)) {
                $findings[] = [
                    'type'       => 'SUSPICIOUS_TLD_SOURCE',
                    'severity'   => 'HIGH',
                    'package'    => $name,
                    'detail'     => "Package source hosted on high-abuse top-level domain.",
                    'risk_score' => 25,
                ];
            }
        }

        return $findings;
    }
}
