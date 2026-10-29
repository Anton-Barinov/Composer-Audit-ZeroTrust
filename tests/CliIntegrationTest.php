<?php
/**
 * CLI Integration Tests
 * Part of Composer-Audit-ZeroTrust by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

echo "=== Running CLI Integration Test Suite ===\n";

$pass = 0;
$fail = 0;

function assertCli(string $name, bool $condition, string $detail = ''): void {
    global $pass, $fail;
    if ($condition) {
        echo "  [PASS] {$name}" . ($detail ? " -> {$detail}" : "") . "\n";
        $pass++;
    } else {
        echo "  [FAIL] {$name}" . ($detail ? " -> {$detail}" : "") . "\n";
        $fail++;
    }
}

$bin = dirname(__DIR__) . '/bin/composer-zerotrust';

// 1. Version command
$outVer = shell_exec("php {$bin} --version");
assertCli("Version command returns v1.0.0", strpos((string)$outVer, 'v1.0.0') !== false, trim((string)$outVer));

// 2. Scan own repository (must be 100% clean, risk score 0)
$outJson = shell_exec("php {$bin} scan " . dirname(__DIR__) . " --json");
$data = json_decode((string)$outJson, true);

assertCli("Self-scan executes successfully and outputs valid JSON", is_array($data) && ($data['status'] ?? '') === 'success');
assertCli("Self-scan reports 0 risk score (100% clean)", ($data['risk_score'] ?? -1) === 0);

// 3. Scan a directory with crafted malicious fixtures
$fixtureDir = sys_get_temp_dir() . '/czt_fixture_' . uniqid();
mkdir($fixtureDir . '/vendor/bad-pkg', 0777, true);

$composerJson = [
    'name' => 'test/vulnerable-app',
    'require' => [
        'guzlehttp/guzzle' => '^7.0', // Typosquat
    ]
];
file_put_contents($fixtureDir . '/composer.json', json_encode($composerJson));
file_put_contents($fixtureDir . '/vendor/bad-pkg/shell.php', '<?php eval(base64_decode("cGhwaW5mbygpOw==")); ?>');

register_shutdown_function(function() use ($fixtureDir) {
    @unlink($fixtureDir . '/composer.json');
    @unlink($fixtureDir . '/vendor/bad-pkg/shell.php');
    @rmdir($fixtureDir . '/vendor/bad-pkg');
    @rmdir($fixtureDir . '/vendor');
    @rmdir($fixtureDir);
});

$outFixture = shell_exec("php {$bin} scan {$fixtureDir} --json");
$fixtureData = json_decode((string)$outFixture, true);

assertCli(
    "Adversarial fixture triggers issues_found status",
    is_array($fixtureData) && ($fixtureData['status'] ?? '') === 'issues_found'
);
assertCli(
    "Adversarial fixture correctly catches both typosquat and backdoor",
    isset($fixtureData['findings_count']) && $fixtureData['findings_count'] >= 2
);

// 4. CI command exit code verification (should exit 1 on CRITICAL findings)
exec("php {$bin} ci {$fixtureDir}", $ciOutput, $ciExitCode);
assertCli(
    "CI command exits with non-zero code 1 on compromised dependencies",
    $ciExitCode === 1,
    "Exit code was {$ciExitCode}"
);

echo "Results: {$pass} Passed, {$fail} Failed\n\n";
if ($fail > 0) exit(1);
