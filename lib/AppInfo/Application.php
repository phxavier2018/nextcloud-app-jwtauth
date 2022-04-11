<?php
namespace OCA\JwtAuth\AppInfo;

use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;

class Application extends App implements IBootstrap {

	public function __construct() {
		parent::__construct('jwtauth');
	}

	public function register(IRegistrationContext $container): void {
		// Register the composer autoloader for packages shipped by this app, if applicable
		include_once __DIR__ . '/../../vendor/autoload.php';

		//register service
		$container->registerService('jwtAuthTokenParser', function ($c) {
			$config = $c->query(\OCP\IConfig::class);

			return new \OCA\JwtAuth\Helper\JwtAuthTokenParser(
				$config->getSystemConfig()->getValue('jwtauth')['JWKUrl'],
				$config = $c->query(\Psr\Log\LoggerInterface::class),
			);
		});

		$container->registerService('urlGenerator', function ($c) {
			$config = $c->query(\OCP\IConfig::class);

			return new \OCA\JwtAuth\Helper\UrlGenerator(
				$config->getSystemConfig()->getValue('jwtauth')['AutoLoginTriggerUri'],
				$config->getSystemConfig()->getValue('jwtauth')['LogoutConfirmationUri'],
			);
		});

		$container->registerService('loginPageInterceptor', function ($c) {
			return new \OCA\JwtAuth\Helper\LoginPageInterceptor(
				$c->query('urlGenerator'),
				$c->query(\OCP\IUserSession::class),
			);
		});
	}

	public function boot(IBootContext $context): void {
		$container = $context->getAppContainer();
		$loginPageInterceptor = $container->query(\OCA\JwtAuth\Helper\LoginPageInterceptor::class);
		$loginPageInterceptor->intercept();
	}

}
