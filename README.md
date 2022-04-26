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

## Users
- login: phxavier@pomerium.com, password: pxaTESTpomerium1!, role: admin
- login: pxa@pomerium.com, password: pxaTESTpomerium1!, role: member
- login: sep@pomerium.com, password: pxaTESTpomerium1!, role: member

## Installation

A docker-compose file is present, you will just launch it.