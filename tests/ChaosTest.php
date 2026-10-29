<?php
/**
 * Composer-Audit-ZeroTrust Chaos & High-Load Stress Test Suite
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/Config/AuditConfig.php';
require_once dirname(__DIR__) . '/src/Scanner/LockFileAuditor.php';
require_once dirname(__DIR__) . '/src/Scanner/VendorBackdoorScanner.php';
require_once dirname(__DIR__) . '/src/Scanner/TyposquatScanner.php';

use ComposerZeroTrust\Config\AuditConfig;
use ComposerZeroTrust\Scanner\LockFileAuditor;
use ComposerZeroTrust\Scanner\VendorBackdoorScanner;
use ComposerZeroTrust\Scanner\TyposquatScanner;

echo "========================================================\n";
echo "   Running Composer-Audit-ZeroTrust Chaos & Stress Tests\n";
echo "========================================================\n\n";

$passed = 0;
$failed = 0;

function run_test(string $name, callable $fn): void {
    global $passed, $failed;
    echo "Testing {$name}... ";
    try {
        $fn();
        echo "\033[32m[PASS]\033[0m\n";
        $passed++;
    } catch (\Throwable $e) {
        echo "\033[31m[FAIL: " . $e->getMessage() . "]\033[0m\n";
        $failed++;
    }
}

$config = new AuditConfig();

// 1. Stress test with 2,000 package composer.lock
run_test("2,000 Package composer.lock Stress & Memory Benchmark", function() use ($config) {
    $packages = [];
    for ($i = 1; $i <= 2000; $i++) {
        $packages[] = [
            'name'        => "vendor-{$i}/package-{$i}",
            'version'     => "v1." . ($i % 10) . ".0",
            'source'      => [
                'type'      => 'git',
                'url'       => "https://github.com/vendor-{$i}/package-{$i}.git",
                'reference' => 'a1b2c3d4e5f607182930415263748596a7b8c9d0',
            ],
            'dist'        => [
                'type'      => 'zip',
                'url'       => "https://api.github.com/repos/vendor-{$i}/package-{$i}/zipball/abc",
                'reference' => 'a1b2c3d4e5f607182930415263748596a7b8c9d0',
                'shasum'    => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            ],
            'description' => "Test dependency number {$i} in stress suite",
        ];
    }

    $lockData = json_encode(['packages' => $packages, 'packages-dev' => []]);
    $tempFile = tempnam(sys_get_temp_dir(), 'lock_stress_');
    file_put_contents($tempFile, $lockData);

    $memBefore = memory_get_usage(false);
    $timeBefore = microtime(true);

    $auditor = new LockFileAuditor($config);
    $findings = $auditor->audit($tempFile);

    $duration = microtime(true) - $timeBefore;
    $memUsed = (memory_get_usage(false) - $memBefore) / (1024 * 1024);

    unlink($tempFile);

    assert(empty($findings), "Clean 2000 packages should produce zero findings");
    assert($duration < 2.5, "2,000 package audit took {$duration}s (must be < 2.5s)");
    assert($memUsed < 32.0, "Memory used {$memUsed}MB (must be < 32MB)");
});

// 2. Polymorphic Obfuscation Tests
run_test("Polymorphic Hex & Callback Evasion Detection", function() use ($config) {
    $scanner = new VendorBackdoorScanner($config);

    // Evasion A: Hex encoded eval
    $resA = $scanner->analyzeFileContent('hex.php', "<?php \$a = '\\x65\\x76\\x61\\x6c'; eval('\\x3f\\x3e');");
    assert(!empty($resA), "Hex encoded eval must be detected");

    // Evasion B: Variable variable dispatch
    $resB = $scanner->analyzeFileContent('var.php', "<?php \$fn = 'system'; \$\$fn(\$_POST['cmd']);");
    assert(!empty($resB), "Variable variable dispatch must be detected");

    // Evasion C: Array callback assert
    $resC = $scanner->analyzeFileContent('arr.php', "<?php array_filter([\$_GET['x']], 'assert');");
    assert(!empty($resC), "Array callback with assert must be detected");

    // Evasion D: Dynamic reflection dispatch
    $resD = $scanner->analyzeFileContent('ref.php', "<?php (new \\ReflectionFunction('system'))->invoke(\$cmd);");
    assert(!empty($resD), "Reflection dispatch must be detected");
});

// 3. False Positive Resistance on Legitimate Minified Asset
run_test("False Positive Resistance on Non-PHP / Asset Payloads", function() use ($config) {
    $scanner = new VendorBackdoorScanner($config);
    // Typical SVG with base64 data URI embedded inside PHP template
    $cleanTemplate = "<?php echo '<svg src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==\"></svg>';";
    $findings = $scanner->analyzeFileContent('icon.php', $cleanTemplate);
    assert(empty($findings), "Valid base64 data-URI must not be flagged as a backdoor");
});

// 4. ReDoS Immunity on Extreme Adversarial Strings (50,000 chars)
run_test("ReDoS Resistance & Sub-50ms Execution on 50,000-char Strings", function() use ($config) {
    $scanner = new VendorBackdoorScanner($config);
    // Adversarial nested traversal pattern and long repetitive whitespace
    $adversarialContent = "<?php " . str_repeat('/../../vendor/..', 3000) . str_repeat(' ', 20000) . "// normal comment\n";
    $start = microtime(true);
    $findings = $scanner->analyzeFileContent('redos_test.php', $adversarialContent);
    $elapsedMs = (microtime(true) - $start) * 1000;
    assert($elapsedMs < 50.0, "Scan must complete in < 50ms without ReDoS backtracking (took {$elapsedMs}ms)");
});

// 5. Garbage Data Fuzzing on composer.lock
run_test("Garbage Data Fuzzing & Malformed Lock-File Handling", function() use ($config) {
    $auditor = new LockFileAuditor($config);

    // Case A: Missing lock file
    $resA = $auditor->audit('/non_existent_file_path_' . uniqid() . '.lock');
    assert(!empty($resA) && $resA[0]['type'] === 'MISSING_LOCK_FILE');

    // Case B: Corrupted JSON
    $corruptedFile = tempnam(sys_get_temp_dir(), 'corrupt_lock_');
    file_put_contents($corruptedFile, '{"packages": [BROKEN_JSON');
    $resB = $auditor->audit($corruptedFile);
    unlink($corruptedFile);
    assert(!empty($resB) && $resB[0]['type'] === 'CORRUPTED_LOCK_FILE');

    // Case C: Garbage type confusion (packages is a string instead of array)
    $typeConfusedFile = tempnam(sys_get_temp_dir(), 'type_confuse_');
    file_put_contents($typeConfusedFile, json_encode(['packages' => 'garbage_string', 'packages-dev' => 12345]));
    $resC = $auditor->audit($typeConfusedFile);
    unlink($typeConfusedFile);
    assert(is_array($resC), "Type confused lock must return array without crashing");

    // Case D: Packages containing invalid element types
    $pkgElementFile = tempnam(sys_get_temp_dir(), 'pkg_elem_');
    file_put_contents($pkgElementFile, json_encode(['packages' => ['not_an_array', 42, null, true]]));
    $resD = $auditor->audit($pkgElementFile);
    unlink($pkgElementFile);
    assert(is_array($resD), "Invalid package elements must be safely ignored");
});

echo "\n--------------------------------------------------------\n";
echo "Chaos Results: {$passed} Passed, {$failed} Failed\n";
echo "--------------------------------------------------------\n";

if ($failed === 0) {
    echo "🎉 ALL COMPOSER-AUDIT CHAOS TESTS PASSED CLEANLY!\n";
    exit(0);
} else {
    exit(1);
}
