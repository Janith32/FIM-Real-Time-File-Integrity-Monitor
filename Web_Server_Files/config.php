<?php
/**
 * TechSolutions Lanka - Application Configuration
 * SENSITIVE FILE - DO NOT EXPOSE PUBLICLY
 */

define('DB_HOST',     'localhost');
define('DB_NAME',     'techsolutions_prod');
define('DB_USER',     'ts_app_user');
define('DB_PASS',     'Pr0d_S3cur3_2025!');
define('DB_PORT',     3306);

define('APP_ENV',     'production');
define('APP_DEBUG',   false);
define('APP_KEY',     'base64:mN8kQpLwXzYvRtJhCsFdGuEbOaInPmKl');
define('APP_URL',     'https://techsolutions.lk');

define('MAIL_HOST',   'smtp.techsolutions.lk');
define('MAIL_PORT',   587);
define('MAIL_USER',   'no-reply@techsolutions.lk');
define('MAIL_PASS',   'M4il_S3rv!ce_Key');

define('SESSION_TIMEOUT', 1800);
define('MAX_LOGIN_ATTEMPTS', 5);
?>
