<?php
/**
 * Composer-Audit-ZeroTrust: Central Execution Engine
 * Part of Composer-Audit-ZeroTrust by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

namespace ComposerZeroTrust;

use ComposerZeroTrust\Config\AuditConfig;
use ComposerZeroTrust\Report\AuditReport;
use ComposerZeroTrust\Scanner\LockFileAuditor;
use ComposerZeroTrust\Scanner\TyposquatScanner;
use ComposerZeroTrust\Scanner\VendorBackdoorScanner;

class ZeroTrustEngine
{
    private AuditConfig $config;
    private TyposquatScanner $typosquatScanner;
    private VendorBackdoorScanner $backdoorScanner;
    private LockFileAuditor $lockAuditor;

    public function __construct(?AuditConfig $config = null)
    {
        $this->config = $config ?? new AuditConfig();
        $this->typosquatScanner = new TyposquatScanner($this->config);
        $this->backdoorScanner = new VendorBackdoorScanner($this->config);
        $this->lockAuditor = new LockFileAuditor($this->config);
    }

    public function runAudit(string $projectPath): AuditReport
    {
        $t0 = microtime(true);
        $projectPath = rtrim($projectPath, '/');
        $report = new AuditReport();

        $composerJsonFile = $projectPath . '/composer.json';
        $composerLockFile = $projectPath . '/composer.lock';
        $vendorDir = $projectPath . '/vendor';

        $packagesToScan = [];

        // 1. Extract packages from composer.json
        if (file_exists($composerJsonFile)) {
            $json = json_decode((string)file_get_contents($composerJsonFile), true);
            if (is_array($json)) {
                $packagesToScan = array_merge(
                    $packagesToScan,
                    $json['require'] ?? [],
                    $json['require-dev'] ?? []
                );
            }
        }

        // 2. Extract packages from composer.lock
        if (file_exists($composerLockFile)) {
            $lock = json_decode((string)file_get_contents($composerLockFile), true);
            if (is_array($lock)) {
                $lockPackages = array_merge(
                    $lock['packages'] ?? [],
                    $lock['packages-dev'] ?? []
                );
                foreach ($lockPackages as $pkg) {
                    if (isset($pkg['name'])) {
                        $packagesToScan[$pkg['name']] = $pkg['version'] ?? '*';
                    }
                }
            }
        }

        // Exclude php, ext-* platform requirements
        $cleanPackages = [];
        foreach ($packagesToScan as $name => $ver) {
            if ($name === 'php' || str_starts_with($name, 'ext-')) {
                continue;
            }
            $cleanPackages[$name] = $ver;
        }

        // 3. Run Typosquatting Scanner
        $typosquatFindings = $this->typosquatScanner->scan($cleanPackages);
        $report->addFindings($typosquatFindings);

        // 4. Run Lock File Integrity Auditor
        $lockFindings = $this->lockAuditor->audit($composerLockFile);
        $report->addFindings($lockFindings);

        // 5. Run Vendor Backdoor & Heuristic Scanner
        $vendorFindings = [];
        $filesCount = 0;
        if (is_dir($vendorDir)) {
            $vendorFindings = $this->backdoorScanner->scan($vendorDir);
            $report->addFindings($vendorFindings);

            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($vendorDir, \RecursiveDirectoryIterator::SKIP_DOTS));
            $filesCount = iterator_count($it);
        }

        $duration = microtime(true) - $t0;
        $report->setStats(count($cleanPackages), $filesCount, $duration);

        return $report;
    }
}
