# Nextcloud JWT Auth app

A [Nextcloud](https://nextcloud.com/) (v23+) application which lets you auto-login users ([single-sign-on](https://en.wikipedia.org/wiki/Single_sign-on)) without them having to go through the Nextcloud login page.

To make use of this app, you need  an identity-aware access proxy[pomerium](https://github.com/pomerium/pomerium) , serving as a login identifier.
The JWT Auth Nextcloud application securely processes these tokens and transparently logs the user into Nextcloud.

**Note**: Nextcloud v23+ is required.


## Flow

1. A user visits any Nextcloud page which requires authentication

2. If the user is not logged in, pomerium redirect to keycloak

3. If not already logged in, the user follows steps which log them into your other (Identity Provider) system

4. The JWT Auth app validates the JWT token, and if trusted, transparently (without user action) logs the user into Nextcloud

## Prerequisites for using

- another system which would assist in handling login requests for users. Let's call it an **Identity Provider** and an identity-aware access proxy.

## Config

All configuration for the app is directly picked up from Nextcloud's system configuration file (`config.php`). The following properties (with their descriptions) are valid configuration entries.

```php
$CONFIG = array (
  //your nextcloud config
  //configurations used by the app
  'jwtauth' => 
    array (
		//redirect to the app and login into nextcloud
		'AutoLoginTriggerUri' => 'https://nextcloud.localhost.pomerium.io/apps/jwtauth',
		//logout uri, logout of nextcloud, pomerium and keycloak
		'LogoutConfirmationUri' => 'https://keycloak.localhost.pomerium.io/auth/realms/demo/protocol/openid-connect/logout?post_logout_redirect_uri=https://nextcloud.localhost.pomerium.io',
		//header name containing the token (set for example in configuration of nginx)
		'RequestHeader' => 'x-pomerium-jwt-assertion',
		//uri of jks endpoint
		'JWKUrl' => 'https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json',
		//wich claim name is used for the username in the token
		'UsernameClaim' => 'preferred_username',
		//which claim name is used for display name of user in the token
		'DisplaynameClaim' => 'name',
		//wich claim name is used for the email in the token
		'EmailClaim' => 'email',
		//which claim name is used for group mapping in the token
		'GroupsClaim' => 'client_roles',
		//which roles exists in keycloak and could be set in the token
		'Roles' => ['admin','member'],
	),
);
```

## Installation

This JWT Auth Nextcloud application is not available on the Nextcloud [App Store](https://apps.nextcloud.com/) yet, so you **need to install it manually**.

To install it, place its files in a `apps/jwtauth` directory.

Then install the app's dependencies using [composer](https://getcomposer.org/): `cd apps/jwtauth; make composer; cd ..`

After that, specify the required [Application configuration values](#application-configuration-values). Example:

```bash
./occ config:system:set jwtauth AutoLoginTriggerUri --value="https://your-other-system/nextcloud/auto-login?targetPath=__TARGET_PATH__"

./occ config:system:set jwtauth LogoutConfirmationUri --value="https://your-other-system/nextcloud/nextcloud/logged-out"

./occ config:system:set jwtauth SharedSecret --value="jJJ@wPHNNnLVLd!@__wkqLFbLd9tT!VXjkC973xMR!7cjvz4WfFgWRstH"
```

Finally, enable the app: `./occ app:enable jwtauth`.

From that point on, the Nextcloud `/login` page will be unavailable.
(A way to get to it is to access it using `/login?forceStay=1`.)

All other requests to the `/login` page would be automatically captured and directed to your Identity Provider system (e.g. `https://your-other-system/nextcloud/auto-login`), before being brought back to Nextcloud.
