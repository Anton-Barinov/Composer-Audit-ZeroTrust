<?php
/**
 * Composer-Audit-ZeroTrust: Audit Reporter & Risk Scoring Engine
 * Part of Composer-Audit-ZeroTrust by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

namespace ComposerZeroTrust\Report;

class AuditReport
{
    /** @var array<int, array<string, mixed>> */
    private array $findings = [];
    private float $executionTime = 0.0;
    private int $packagesScanned = 0;
    private int $filesScanned = 0;

    public function addFindings(array $findings): void
    {
        foreach ($findings as $f) {
            $this->findings[] = $f;
        }
    }

    public function setStats(int $packagesScanned, int $filesScanned, float $executionTime): void
    {
        $this->packagesScanned = $packagesScanned;
        $this->filesScanned = $filesScanned;
        $this->executionTime = $executionTime;
    }

    public function getFindings(): array
    {
        return $this->findings;
    }

    public function getRiskScore(): int
    {
        $total = 0;
        foreach ($this->findings as $f) {
            $total += (int)($f['risk_score'] ?? 10);
        }
        return min(100, $total);
    }

    public function getRiskLevel(): string
    {
        $score = $this->getRiskScore();
        if ($score >= 70) return 'CRITICAL';
        if ($score >= 40) return 'HIGH';
        if ($score >= 15) return 'ELEVATED';
        return 'SECURE';
    }

    public function hasCriticalFindings(): bool
    {
        foreach ($this->findings as $f) {
            if (($f['severity'] ?? '') === 'CRITICAL') {
                return true;
            }
        }
        return false;
    }

    public function toCliOutput(): string
    {
        $score = $this->getRiskScore();
        $level = $this->getRiskLevel();

        $color = match ($level) {
            'CRITICAL' => "\033[1;31m",
            'HIGH'     => "\033[1;33m",
            'ELEVATED' => "\033[1;35m",
            default    => "\033[1;32m",
        };
        $reset = "\033[0m";

        $out = "\n======================================================================\n";
        $out .= "  🔍 COMPOSER ZERO-TRUST SUPPLY-CHAIN SECURITY AUDIT REPORT\n";
        $out .= "======================================================================\n\n";

        $out .= "  Scanned Packages:    " . number_format($this->packagesScanned) . "\n";
        $out .= "  Scanned Vendor Files:" . number_format($this->filesScanned) . "\n";
        $out .= "  Audit Duration:      " . round($this->executionTime * 1000, 2) . " ms\n";
        $out .= "  Total Findings:      " . count($this->findings) . "\n";
        $out .= "  Supply-Chain Score:  {$color}{$score} / 100 [{$level}]{$reset}\n\n";

        if (empty($this->findings)) {
            $out .= "  \033[1;32m✅ ZERO SUPPLY-CHAIN THREATS DETECTED! All dependencies verified clean.\033[0m\n\n";
            return $out;
        }

        $out .= "----------------------------------------------------------------------\n";
        $out .= "  DETAILED INCIDENTS & THREAT VECTORS:\n";
        $out .= "----------------------------------------------------------------------\n";

        foreach ($this->findings as $i => $f) {
            $num = $i + 1;
            $sevColor = ($f['severity'] === 'CRITICAL') ? "\033[1;31m" : "\033[1;33m";
            $out .= "\n  [#{$num}] {$sevColor}[{$f['severity']}] {$f['type']}{$reset}\n";
            if (isset($f['package'])) {
                $out .= "      Package:  \033[1;36m{$f['package']}\033[0m\n";
            }
            if (isset($f['target'])) {
                $out .= "      Target:   \033[1;32m{$f['target']}\033[0m (Legitimate Canonical)\n";
            }
            if (isset($f['file'])) {
                $out .= "      File:     \033[1;37m{$f['file']}" . (isset($f['line']) ? ":{$f['line']}" : "") . "\033[0m\n";
            }
            if (isset($f['snippet'])) {
                $out .= "      Snippet:  \033[0;33m{$f['snippet']}\033[0m\n";
            }
            $out .= "      Details:  {$f['detail']}\n";
        }

        $out .= "\n======================================================================\n";
        $out .= "  RECOMMENDED REMEDIATION:\n";
        $out .= "  1. Immediately review or remove the flagged packages from composer.json.\n";
        $out .= "  2. For typosquatted packages, update to the legitimate target namespace.\n";
        $out .= "  3. Re-run `composer update --lock` after purging suspect packages.\n";
        $out .= "======================================================================\n\n";

        return $out;
    }

    public function toJson(): string
    {
        return json_encode([
            'status'             => empty($this->findings) ? 'success' : 'issues_found',
            'risk_score'         => $this->getRiskScore(),
            'risk_level'         => $this->getRiskLevel(),
            'packages_scanned'   => $this->packagesScanned,
            'files_scanned'      => $this->filesScanned,
            'duration_ms'        => round($this->executionTime * 1000, 2),
            'findings_count'     => count($this->findings),
            'findings'           => $this->findings,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
