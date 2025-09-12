<?php

// Load WordPress test environment
if (!defined('WP_TESTS_DIR')) {
    define('WP_TESTS_DIR', '/tmp/wordpress-tests-lib/');
}

// Load WordPress
require_once WP_TESTS_DIR . 'includes/functions.php';

function _manually_load_plugin()
{
    require __DIR__ . '/../repo-manager.php';
}

tests_add_filter('muplugins_loaded', '_manually_load_plugin');

require WP_TESTS_DIR . 'includes/bootstrap.php';

// Load our plugin
_manually_load_plugin();
