<?php
/**
 * Composer-Audit-ZeroTrust: Vendor Backdoor & Obfuscated Web-Shell Scanner
 * Part of Composer-Audit-ZeroTrust by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

namespace ComposerZeroTrust\Scanner;

use ComposerZeroTrust\Config\AuditConfig;

class VendorBackdoorScanner
{
    private AuditConfig $config;

    public function __construct(AuditConfig $config)
    {
        $this->config = $config;
    }

    /**
     * Recursively scan vendor directory for malicious signatures and heuristics
     * 
     * @param string $vendorDir
     * @return array<int, array<string, mixed>>
     */
    public function scan(string $vendorDir): array
    {
        $findings = [];
        if (!is_dir($vendorDir)) {
            return $findings;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($vendorDir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if (!$file->isFile()) {
                continue;
            }

            $ext = strtolower($file->getExtension());
            if (!in_array($ext, ['php', 'inc', 'phtml', 'phar'], true)) {
                continue;
            }

            $filePath = $file->getPathname();

            // Skip test fixtures in third-party libraries if configured or standard
            if ($this->shouldSkipFile($filePath)) {
                continue;
            }

            $content = (string)@file_get_contents($filePath);
            if ($content === '') {
                continue;
            }

            $fileFindings = $this->analyzeFileContent($filePath, $content);
            foreach ($fileFindings as $f) {
                $findings[] = $f;
            }
        }

        return $findings;
    }

    /**
     * Analyze a single PHP file's content
     */
    public function analyzeFileContent(string $filePath, string $content): array
    {
        $findings = [];

        // 1. Critical Obfuscated Execution Patterns (eval + decompress / decode / hex / callbacks)
        $obfuscationPatterns = [
            'EVAL_BASE64_OBFUSCATION'       => '/eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i',
            'ASSERT_BASE64_EXEC'            => '/assert\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(/i',
            'PREG_REPLACE_EVAL'             => '/preg_replace\s*\(\s*[\'"][^\'"]*\/e[\'"]\s*,/i',
            'CREATE_FUNCTION_EVAL'          => '/create_function\s*\([^,]+,\s*(?:base64_decode|gzinflate)/i',
            'HEX_ENCODED_EXECUTION'         => '/(?:\\\\x65\\\\x76\\\\x61\\\\x6c|eval\s*\(\s*[\'"]?\\\\x[0-9a-f]{2})/i',
            'VARIABLE_FUNCTION_DISPATCH'    => '/\$\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[/i',
            'ARRAY_CALLBACK_DISPATCH'       => '/(?:array_map|array_filter|array_walk)\s*\(\s*[^,]+,\s*[\'"](?:assert|system|passthru|shell_exec)[\'"]\s*\)/i',
            'REFLECTION_CALL_DISPATCH'      => '/new\s+\\\\?ReflectionFunction\s*\(\s*[\'"](?:system|exec|passthru|shell_exec|assert)[\'"]\s*\)/i',
        ];

        foreach ($obfuscationPatterns as $type => $pattern) {
            if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                $line = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                $findings[] = [
                    'type'       => $type,
                    'severity'   => 'CRITICAL',
                    'file'       => $filePath,
                    'line'       => $line,
                    'snippet'    => trim(substr($matches[0][0], 0, 80)),
                    'detail'     => "Malicious obfuscation pattern detected: dynamic code execution via unpacker/decoder.",
                    'risk_score' => 50,
                ];
            }
        }

        // 2. Secret Snooping & Exfiltration (Targeting APP_KEY, AWS_KEY, DB_PASSWORD)
        $hasSecretSnoop = preg_match('/(?:getenv|get_cfg_var|\$_ENV|\$_SERVER)\s*(?:\(|\s*\[\s*)[\'"](?:APP_KEY|AWS_SECRET_ACCESS_KEY|DB_PASSWORD|SECRET_KEY|SSH_PRIVATE_KEY)[\'"]/i', $content, $snoopMatch, PREG_OFFSET_CAPTURE);
        $hasOutboundNetwork = preg_match('/(?:curl_exec|file_get_contents\s*\(\s*[\'"]https?:\/\/|fsockopen|stream_socket_client|dns_get_record)/i', $content);

        if ($hasSecretSnoop && $hasOutboundNetwork) {
            $line = substr_count(substr($content, 0, $snoopMatch[0][1]), "\n") + 1;
            $findings[] = [
                'type'       => 'SECRET_EXFILTRATION_BEACON',
                'severity'   => 'CRITICAL',
                'file'       => $filePath,
                'line'       => $line,
                'snippet'    => trim(substr($snoopMatch[0][0], 0, 80)),
                'detail'     => "Suspicious telemetry/exfiltration beacon: reads sensitive application secrets and connects to outbound network.",
                'risk_score' => 50,
            ];
        }

        // 3. Reverse Shell & Unsanitized System Calls
        $shellPatterns = [
            'BASH_DEV_TCP_REVERSESHELL' => '/\/dev\/tcp\/[0-9.]+\/[0-9]+/i',
            'NETCAT_REVERSESHELL'       => '/(?:nc|netcat)\s+.*-e\s+\/bin\/(?:ba)?sh/i',
            'PROC_OPEN_INTERACTIVE_SH'  => '/proc_open\s*\(\s*[\'"](?:\/bin\/)?(?:ba)?sh\s+-i/i',
        ];

        foreach ($shellPatterns as $type => $pattern) {
            if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                $line = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                $findings[] = [
                    'type'       => $type,
                    'severity'   => 'CRITICAL',
                    'file'       => $filePath,
                    'line'       => $line,
                    'snippet'    => trim(substr($matches[0][0], 0, 80)),
                    'detail'     => "Interactive reverse shell signature detected in dependency code.",
                    'risk_score' => 50,
                ];
            }
        }

        // 4. Shannon Entropy Analysis for Packed / Obfuscated Strings
        $highEntropyStrings = $this->detectHighEntropyBlocks($content);
        foreach ($highEntropyStrings as $entry) {
            $findings[] = [
                'type'       => 'SUSPICIOUS_HIGH_ENTROPY_BLOB',
                'severity'   => 'HIGH',
                'file'       => $filePath,
                'line'       => $entry['line'],
                'snippet'    => substr($entry['sample'], 0, 60) . '... (length: ' . $entry['length'] . ')',
                'detail'     => "High Shannon entropy string (" . round($entry['entropy'], 2) . " bits/char). High probability of packed or encrypted malicious payload.",
                'risk_score' => 25,
            ];
        }

        return $findings;
    }

    /**
     * Compute Shannon Entropy: H(X) = - sum(p * log2(p))
     */
    public function computeEntropy(string $data): float
    {
        $len = strlen($data);
        if ($len === 0) {
            return 0.0;
        }

        $frequencies = count_chars($data, 1);
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }

    /**
     * Scan lines for strings with high entropy exceeding safe threshold
     */
    private function detectHighEntropyBlocks(string $content): array
    {
        $results = [];
        $lines = explode("\n", $content);
        $threshold = $this->config->getEntropyThreshold();

        foreach ($lines as $lineNum => $line) {
            // Find quoted string literals of substantial length (> 120 chars)
            if (preg_match_all('/([\'"])([a-zA-Z0-9+\/=_~-]{120,})\1/', $line, $matches)) {
                foreach ($matches[2] as $candidate) {
                    $entropy = $this->computeEntropy($candidate);
                    if ($entropy >= $threshold) {
                        $results[] = [
                            'line'    => $lineNum + 1,
                            'entropy' => $entropy,
                            'length'  => strlen($candidate),
                            'sample'  => $candidate,
                        ];
                    }
                }
            }
        }

        return $results;
    }

    private function shouldSkipFile(string $filePath): bool
    {
        if ($this->config->isPathIgnored($filePath)) {
            return true;
        }

        // Avoid checking composer internal metadata or testing fixtures in phpunit
        if (strpos($filePath, '/vendor/composer/') !== false ||
            strpos($filePath, '/tests/') !== false ||
            strpos($filePath, '/Tests/') !== false) {
            return true;
        }

        return false;
    }
}
