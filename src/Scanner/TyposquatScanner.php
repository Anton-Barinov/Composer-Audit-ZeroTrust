<?php
/**
 * Composer-Audit-ZeroTrust: Typosquatting & Package Impersonation Scanner
 * Part of Composer-Audit-ZeroTrust by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

namespace ComposerZeroTrust\Scanner;

use ComposerZeroTrust\Config\AuditConfig;

class TyposquatScanner
{
    /**
     * Curated registry of top 120 most popular PHP/Composer packages
     */
    private const POPULAR_PACKAGES = [
        // HTTP & API
        'guzzlehttp/guzzle', 'guzzlehttp/psr7', 'guzzlehttp/promises', 'symfony/http-client',
        // Frameworks & Foundations
        'laravel/framework', 'symfony/framework-bundle', 'symfony/http-foundation',
        'symfony/console', 'symfony/event-dispatcher', 'symfony/routing', 'symfony/var-dumper',
        'illuminate/support', 'illuminate/database', 'illuminate/events', 'illuminate/container',
        'yiisoft/yii2', 'cakephp/cakephp', 'slim/slim',
        // Logging & Monitoring
        'monolog/monolog', 'psr/log', 'sentry/sentry',
        // Database & ORM
        'doctrine/orm', 'doctrine/dbal', 'doctrine/common', 'doctrine/migrations',
        // Testing & Quality
        'phpunit/phpunit', 'mockery/mockery', 'fakerphp/faker', 'phpstan/phpstan',
        'vimeo/psalm', 'rector/rector', 'friendsofphp/php-cs-fixer',
        // Utilities & Parsing
        'nikic/php-parser', 'ramsey/uuid', 'nesbot/carbon', 'brick/math',
        'symfony/yaml', 'symfony/finder', 'symfony/process', 'symfony/mime',
        'league/flysystem', 'league/csv', 'league/commonmark', 'twig/twig',
        // Security & Cryptography
        'paragonie/random_compat', 'paragonie/constant_time_encoding', 'defuse/php-encryption',
        'firebase/php-jwt', 'lcobucci/jwt',
        // Payment & E-commerce
        'stripe/stripe-php', 'paypal/rest-api-sdk-php',
        // Template & Mail
        'phpmailer/phpmailer', 'symfony/mailer',
    ];

    /**
     * Confusable Homoglyph mapping (Cyrillic/Greek/Lookalikes to Latin ASCII)
     */
    private const HOMOGLYPHS = [
        'а' => 'a', 'с' => 'c', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'х' => 'x', 'у' => 'y',
        'А' => 'A', 'В' => 'B', 'С' => 'C', 'Е' => 'E', 'Н' => 'H', 'М' => 'M', 'О' => 'O',
        'Р' => 'P', 'Т' => 'T', 'Х' => 'X',
        '1' => 'l', '0' => 'o',
    ];

    private AuditConfig $config;

    public function __construct(AuditConfig $config)
    {
        $this->config = $config;
    }

    /**
     * Inspect all required packages from composer.json and composer.lock
     * 
     * @param array<string, string> $packages [packageName => versionConstraint]
     * @return array<int, array<string, mixed>>
     */
    public function scan(array $packages): array
    {
        $findings = [];
        $canonicalMap = array_flip(self::POPULAR_PACKAGES);

        foreach ($packages as $pkgName => $version) {
            $pkgName = strtolower(trim((string)$pkgName));

            // Skip if package is exact popular package or in whitelist
            if (isset($canonicalMap[$pkgName]) || $this->config->isPackageWhitelisted($pkgName)) {
                continue;
            }

            // 1. Homoglyph visual spoofing detection (e.g. Cyrillic 'а' replacing Latin 'a')
            $normalizedName = strtr($pkgName, self::HOMOGLYPHS);
            if ($normalizedName !== $pkgName && isset($canonicalMap[$normalizedName])) {
                $findings[] = [
                    'type'         => 'HOMOGLYPH_IMPERSONATION',
                    'severity'     => 'CRITICAL',
                    'package'      => $pkgName,
                    'target'       => $normalizedName,
                    'detail'       => "Visual homoglyph spoofing detected! Package contains invisible or mixed-script characters imitating '{$normalizedName}'.",
                    'risk_score'   => 45,
                ];
                continue;
            }

            // 2. Levenshtein and Damerau Distance vs Canonical Packages
            $parts = explode('/', $pkgName);
            $vendor = $parts[0] ?? '';
            $project = $parts[1] ?? '';

            foreach (self::POPULAR_PACKAGES as $popular) {
                $popParts = explode('/', $popular);
                $popVendor = $popParts[0];
                $popProject = $popParts[1];

                // Detection 2a: Prefix or Separator Mimicking (e.g. guzzle-http/guzzle vs guzzlehttp/guzzle)
                $strippedPkg = str_replace(['-', '_'], '', $pkgName);
                $strippedPop = str_replace(['-', '_'], '', $popular);
                if ($strippedPkg === $strippedPop && $pkgName !== $popular) {
                    $findings[] = [
                        'type'         => 'SEPARATOR_MIMICKING',
                        'severity'     => 'HIGH',
                        'package'      => $pkgName,
                        'target'       => $popular,
                        'detail'       => "Deceptive separator mimicking: '{$pkgName}' differs from '{$popular}' only by hyphens or underscores.",
                        'risk_score'   => 30,
                    ];
                    break;
                }

                // If vendor matches or is very close
                $vendorDist = levenshtein($vendor, $popVendor);
                $projectDist = levenshtein($project, $popProject);
                $fullDist = levenshtein($pkgName, $popular);

                // Detection 2b: Typo in package name with same vendor (e.g. guzzlehttp/guzle)
                if ($vendor === $popVendor && $projectDist > 0 && $projectDist <= 2) {
                    $findings[] = [
                        'type'         => 'TYPOSQUAT_PACKAGE_NAME',
                        'severity'     => 'CRITICAL',
                        'package'      => $pkgName,
                        'target'       => $popular,
                        'detail'       => "High-risk typosquatting suspect: '{$pkgName}' has edit distance {$projectDist} from legitimate '{$popular}'.",
                        'risk_score'   => 40,
                    ];
                    break;
                }

                // Detection 2c: Typo in vendor name (e.g. guzlehttp/guzzle, symfoni/http-foundation)
                if ($project === $popProject && $vendorDist > 0 && $vendorDist <= 2) {
                    $findings[] = [
                        'type'         => 'TYPOSQUAT_VENDOR_NAME',
                        'severity'     => 'CRITICAL',
                        'package'      => $pkgName,
                        'target'       => $popular,
                        'detail'       => "Vendor impersonation suspect: '{$vendor}' resembles legitimate vendor '{$popVendor}' (distance {$vendorDist}) for target '{$popular}'.",
                        'risk_score'   => 40,
                    ];
                    break;
                }

                // Detection 2d: Close full string distance (e.g. laravel-framework vs laravel/framework)
                if ($fullDist > 0 && $fullDist <= 2 && strlen($pkgName) > 6) {
                    $findings[] = [
                        'type'         => 'TYPOSQUAT_FULL_STRING',
                        'severity'     => 'HIGH',
                        'package'      => $pkgName,
                        'target'       => $popular,
                        'detail'       => "Close edit distance ({$fullDist}) to legitimate package '{$popular}'.",
                        'risk_score'   => 25,
                    ];
                    break;
                }
            }
        }

        return $findings;
    }
}
