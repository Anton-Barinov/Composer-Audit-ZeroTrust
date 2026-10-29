<?php
/**
 * TyposquatScanner Unit Tests
 * Part of Composer-Audit-ZeroTrust by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/Config/AuditConfig.php';
require_once dirname(__DIR__) . '/src/Scanner/TyposquatScanner.php';

use ComposerZeroTrust\Config\AuditConfig;
use ComposerZeroTrust\Scanner\TyposquatScanner;

echo "=== Running TyposquatScanner Test Suite ===\n";

$pass = 0;
$fail = 0;

function assertTest(string $name, bool $condition, string $detail = ''): void {
    global $pass, $fail;
    if ($condition) {
        echo "  [PASS] {$name}" . ($detail ? " -> {$detail}" : "") . "\n";
        $pass++;
    } else {
        echo "  [FAIL] {$name}" . ($detail ? " -> {$detail}" : "") . "\n";
        $fail++;
    }
}

$config = new AuditConfig();
$scanner = new TyposquatScanner($config);

// 1. Typosquat in Vendor Name (guzlehttp vs guzzlehttp)
$findings1 = $scanner->scan(['guzlehttp/guzzle' => '^7.0']);
assertTest(
    "Detects vendor typosquatting (guzlehttp vs guzzlehttp)",
    count($findings1) === 1 && $findings1[0]['type'] === 'TYPOSQUAT_VENDOR_NAME',
    $findings1 ? $findings1[0]['detail'] : ''
);

// 2. Typosquat in Package Name (monolog/monologg vs monolog/monolog)
$findings2 = $scanner->scan(['monolog/monologg' => '^2.0']);
assertTest(
    "Detects package name typosquatting (monologg vs monolog)",
    count($findings2) === 1 && $findings2[0]['type'] === 'TYPOSQUAT_PACKAGE_NAME',
    $findings2 ? $findings2[0]['detail'] : ''
);

// 3. Homoglyph Visual Spoofing (Cyrillic 'а' replacing Latin 'a')
// 'l' . "\xd0\xb0" . 'ravel/framework' -> 'lаravel/framework'
$cyrillicA = "\xd0\xb0";
$fakeLaravel = "l{$cyrillicA}ravel/framework";
$findings3 = $scanner->scan([$fakeLaravel => '^10.0']);
assertTest(
    "Detects Cyrillic Homoglyph visual spoofing attack",
    count($findings3) === 1 && $findings3[0]['type'] === 'HOMOGLYPH_IMPERSONATION',
    $findings3 ? $findings3[0]['detail'] : ''
);

// 4. Separator Deception (guzzle-http/guzzle vs guzzlehttp/guzzle)
$findings4 = $scanner->scan(['guzzle-http/guzzle' => '^7.0']);
assertTest(
    "Detects deceptive hyphen separator mimicking",
    count($findings4) === 1 && $findings4[0]['type'] === 'SEPARATOR_MIMICKING',
    $findings4 ? $findings4[0]['detail'] : ''
);

// 5. Legitimate Package (No False Positive)
$findings5 = $scanner->scan(['guzzlehttp/guzzle' => '^7.0', 'symfony/console' => '^6.0']);
assertTest(
    "Legitimate canonical packages produce zero findings",
    count($findings5) === 0
);

echo "Results: {$pass} Passed, {$fail} Failed\n\n";
if ($fail > 0) exit(1);
