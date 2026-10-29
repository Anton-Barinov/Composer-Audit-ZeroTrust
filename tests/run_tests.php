<?php
/**
 * Master Test Suite Runner for Composer-Audit-ZeroTrust
 * Part of Composer-Audit-ZeroTrust by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

echo "====================================================\n";
echo "   Composer-Audit-ZeroTrust Master Test Suite\n";
echo "====================================================\n\n";

$tests = [
    'TyposquatTest.php',
    'BackdoorScannerTest.php',
    'LockFileAuditorTest.php',
    'CliIntegrationTest.php',
    'ChaosTest.php',
];

$allPassed = true;
$startTime = microtime(true);

foreach ($tests as $test) {
    $filePath = __DIR__ . '/' . $test;
    echo "Running {$test}...\n";
    passthru("php {$filePath}", $exitCode);
    if ($exitCode !== 0) {
        $allPassed = false;
        echo "❌ {$test} failed with exit code {$exitCode}\n\n";
    }
}

$elapsed = round((microtime(true) - $startTime) * 1000, 2);

echo "----------------------------------------------------\n";
if ($allPassed) {
    echo "🎉 ALL TEST SUITES PASSED CLEANLY! ({$elapsed} ms)\n";
    exit(0);
} else {
    echo "❌ SOME TEST SUITES FAILED! ({$elapsed} ms)\n";
    exit(1);
}
