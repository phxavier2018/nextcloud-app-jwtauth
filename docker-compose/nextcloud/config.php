<?php
$CONFIG = array (
'loglevel' => 0,
  'htaccess.RewriteBase' => '/',
  'memcache.local' => '\\OC\\Memcache\\APCu',
  'apps_paths' => 
  array (
    0 => 
    array (
      'path' => '/var/www/html/apps',
      'url' => '/apps',
      'writable' => false,
    ),
    1 => 
    array (
      'path' => '/var/www/html/custom_apps',
      'url' => '/custom_apps',
      'writable' => true,
    ),
  ),
  'instanceid' => 'ocsmig1euto8',
  'passwordsalt' => 'amSmwUbwQe4e8Hud9al9hN100ARd6u',
  'secret' => '8h2Wjaa8N30KR5vqRM2jbaeXCslMiSs2Pwie5lo9kEvohOZ7',
  'trusted_domains' => 
  array (
    0 => 'nextcloud.localhost.pomerium.io',
  ),
  'datadirectory' => '/var/www/html/data',
  'dbtype' => 'mysql',
  'version' => '23.0.3.2',
  'overwrite.cli.url' => 'http://nextcloud.localhost.pomerium.io',
  'dbname' => 'nextcloud',
  'dbhost' => 'mariadb',
  'dbport' => '',
  'dbtableprefix' => 'oc_',
  'mysql.utf8mb4' => true,
  'dbuser' => 'nextcloud',
  'dbpassword' => 'nextcloud',
  'installed' => true,
  'jwtauth' => 
    array (
		'AutoLoginTriggerUri' => 'https://nextcloud.localhost.pomerium.io/apps/jwtauth',
		'LogoutConfirmationUri' => 'https://keycloak.localhost.pomerium.io/auth/realms/demo/protocol/openid-connect/logout?post_logout_redirect_uri=https://nextcloud.localhost.pomerium.io',
		'RequestHeader' => 'x-pomerium-jwt-assertion',
		'JWKUrl' => 'https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json',
		'UsernameClaim' => 'preferred_username',
		'DisplaynameClaim' => 'name',
		'EmailClaim' => 'email',
		'GroupsClaim' => 'client_roles',
		'Roles' => ['admin','member'],
	),
);
