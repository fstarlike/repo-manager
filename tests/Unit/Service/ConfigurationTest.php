<?php

namespace WPGitManager\Tests\Unit\Service;

use PHPUnit\Framework\TestCase;
use WPGitManager\Service\Configuration;

class ConfigurationTest extends TestCase
{
    protected function setUp(): void
    {
        // Reset configuration to defaults
        Configuration::reset();
    }

    protected function tearDown(): void
    {
        // Reset configuration
        Configuration::reset();
    }

    public function testGetDefaultConfiguration()
    {
        $config = Configuration::all();

        $this->assertIsArray($config);
        $this->assertArrayHasKey('security', $config);
        $this->assertArrayHasKey('performance', $config);
        $this->assertArrayHasKey('ui', $config);
        $this->assertArrayHasKey('git', $config);
        $this->assertArrayHasKey('logging', $config);
        $this->assertArrayHasKey('integration', $config);
    }

    public function testGetConfigurationValue()
    {
        $maxExecutionTime = Configuration::get('security.max_execution_time');
        $this->assertEquals(30, $maxExecutionTime);

        $theme = Configuration::get('ui.theme');
        $this->assertEquals('auto', $theme);

        $nonExistent = Configuration::get('non.existent.key', 'default');
        $this->assertEquals('default', $nonExistent);
    }

    public function testSetConfigurationValue()
    {
        Configuration::set('security.max_execution_time', 60);
        $value = Configuration::get('security.max_execution_time');
        $this->assertEquals(60, $value);

        Configuration::set('ui.theme', 'dark');
        $theme = Configuration::get('ui.theme');
        $this->assertEquals('dark', $theme);
    }

    public function testValidateConfiguration()
    {
        $validConfig = [
            'security' => [
                'max_execution_time'      => 30,
                'max_output_size'         => 1048576,
                'rate_limit_max_requests' => 10,
            ],
            'performance' => [
                'cache_ttl'        => 300,
                'max_repositories' => 50,
            ],
            'ui' => [
                'theme' => 'light',
            ],
            'git' => [
                'conflict_resolution' => 'manual',
                'merge_strategy'      => 'merge',
                'push_strategy'       => 'safe',
            ],
        ];

        $errors = Configuration::validate($validConfig);
        $this->assertEmpty($errors);
    }

    public function testValidateInvalidConfiguration()
    {
        $invalidConfig = [
            'security' => [
                'max_execution_time'      => 500, // Too high
                'max_output_size'         => 500, // Too low
                'rate_limit_max_requests' => 150, // Too high
            ],
            'performance' => [
                'cache_ttl'        => 30, // Too low
                'max_repositories' => 2000, // Too high
            ],
            'ui' => [
                'theme' => 'invalid', // Invalid theme
            ],
            'git' => [
                'conflict_resolution' => 'invalid', // Invalid value
                'merge_strategy'      => 'invalid', // Invalid value
                'push_strategy'       => 'invalid', // Invalid value
            ],
        ];

        $errors = Configuration::validate($invalidConfig);
        $this->assertNotEmpty($errors);
        $this->assertCount(8, $errors);
    }

    public function testGetSchema()
    {
        $schema = Configuration::getSchema();

        $this->assertIsArray($schema);
        $this->assertArrayHasKey('security', $schema);
        $this->assertArrayHasKey('performance', $schema);
        $this->assertArrayHasKey('ui', $schema);

        // Check security schema structure
        $securitySchema = $schema['security'];
        $this->assertArrayHasKey('title', $securitySchema);
        $this->assertArrayHasKey('description', $securitySchema);
        $this->assertArrayHasKey('fields', $securitySchema);

        $fields = $securitySchema['fields'];
        $this->assertArrayHasKey('max_execution_time', $fields);
        $this->assertArrayHasKey('max_output_size', $fields);
        $this->assertArrayHasKey('rate_limit_max_requests', $fields);
    }

    public function testExportConfiguration()
    {
        $export = Configuration::export();

        $this->assertIsArray($export);
        $this->assertArrayHasKey('version', $export);
        $this->assertArrayHasKey('timestamp', $export);
        $this->assertArrayHasKey('configuration', $export);
        $this->assertEquals(GIT_MANAGER_VERSION, $export['version']);
    }

    public function testImportConfiguration()
    {
        $configData = [
            'version'       => GIT_MANAGER_VERSION,
            'timestamp'     => current_time('mysql'),
            'configuration' => [
                'security' => [
                    'max_execution_time' => 45,
                ],
                'ui' => [
                    'theme' => 'dark',
                ],
            ],
        ];

        $errors = Configuration::import($configData);
        $this->assertEmpty($errors);

        $this->assertEquals(45, Configuration::get('security.max_execution_time'));
        $this->assertEquals('dark', Configuration::get('ui.theme'));
    }

    public function testImportInvalidConfiguration()
    {
        $invalidData = [
            'configuration' => [
                'security' => [
                    'max_execution_time' => 500, // Invalid
                ],
            ],
        ];

        $errors = Configuration::import($invalidData);
        $this->assertNotEmpty($errors);
    }

    public function testResetConfiguration()
    {
        // Change some values
        Configuration::set('security.max_execution_time', 60);
        Configuration::set('ui.theme', 'dark');

        // Verify changes
        $this->assertEquals(60, Configuration::get('security.max_execution_time'));
        $this->assertEquals('dark', Configuration::get('ui.theme'));

        // Reset
        Configuration::reset();

        // Verify reset to defaults
        $this->assertEquals(30, Configuration::get('security.max_execution_time'));
        $this->assertEquals('auto', Configuration::get('ui.theme'));
    }
}
