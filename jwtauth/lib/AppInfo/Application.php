<?php

declare(strict_types=1);

namespace OCA\JwtAuth\AppInfo;

use OC\AppFramework\Utility\ControllerMethodReflector;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserSession;
use OCP\Util;
use Psr\Log\LoggerInterface;
use OCA\JwtAuth\Service\LoginService;

class Application extends App implements IBootstrap
{
    /** @var IURLGenerator */
    protected $url;

    /** @var Config */
    protected $config;
    private $appName = 'jwtauth';

    public function __construct()
    {
        parent::__construct($this->appName);
    }

    public function register(IRegistrationContext $context): void
    {
		// Register the composer autoloader for packages shipped by this app, if applicable
		include_once __DIR__ . '/../../vendor/autoload.php';
	}

    public function boot(IBootContext $context): void
    {
		$container = $context->getAppContainer();
		$this->url = $container->query(IURLGenerator::class);
		$this->config = $container->query(IConfig::class);
		$request = $container->query(IRequest::class);

		// Get logged in user's session
		$userSession = $container->query(IUserSession::class);
		$session = $container->query(ISession::class);
		$logger = $container->query(LoggerInterface::class);

		// Disable password confirmation for user
		$session->set('last-password-confirm', $container->query(ITimeFactory::class)->getTime());

		/* Redirect to logout URL on completing logout*/
		$logoutUrl = $this->config->getSystemConfig()->getValue('jwtauth')['LogoutConfirmationUri'];
		if (isset($logoutUrl)) {
			$userSession->listen('\OC\User', 'postLogout', function () use ($logoutUrl, $session) {
				// Do nothing if this is a CORS request
				if ($this->getContainer()->query(ControllerMethodReflector::class)->hasAnnotation('CORS')) {
					return;
				}
				// Properly close the session and clear the browsers storage data before
				// redirecting to the logout url.
				$logger->debug("user will be logged out");
				$session->set('clearingExecutionContexts', '1');
				$session->close();
				header('Clear-Site-Data: "*"');
				header('Location: '.$logoutUrl);
				exit();
			});
		}
		//redirect to AutoLoginTriggerUri if set
		$autoLoginTriggerUri = $this->config->getSystemConfig()->getValue('jwtauth')['AutoLoginTriggerUri'];
		if(isset($autoLoginTriggerUri)) {
			if (\array_key_exists('REQUEST_METHOD', $_SERVER)
			&& 'GET' === $_SERVER['REQUEST_METHOD']
			&& '/login' === $request->getPathInfo()
			&& null === $request->getParam('forceStay')
			) {
				$logger->debug('user access login page with the next parameters: '.json_encode($request->getParams()). 'redirecting to /aps/jwtauth');
				header('Location: '.$autoLoginTriggerUri);
				exit();
			}
		}
		
		//verify if user in session is the same of user of payload because pomerium session can ve expired and user changed
		$loginService = $container->query(LoginService::class);
		if(isset($autoLoginTriggerUri)) {
			if(!$loginService->isSameUser($this->config, $request, $userSession)) {
				$logger->debug("user was changed, user will be logged out");
				$userSession->logout();
				$session->set('clearingExecutionContexts', '1');
				$session->close();
				header('Clear-Site-Data: "*"');
				header('Location: '.$autoLoginTriggerUri);
				exit();
			}
		}
	}
}
