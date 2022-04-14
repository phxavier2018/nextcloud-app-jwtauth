<?php
namespace OCA\JwtAuth\Controller;

use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Controller;

class LoginController extends Controller {

	/**
	 * @var \OCP\IConfig
	 */
	private $config;

	/**
	 * @var \OCP\IUserManager
	 */
	private $userManager;

	/**
	 * @var \OCP\IUserSession
	 */
	private $session;

	/**
	 * @var \OCA\JwtAuth\Helper\LoginChain
	 */
	private $loginChain;

	/**
	 * @var \OCA\JwtAuth\Helper\JwtAuthTokenParser
	 */
	private $jwtAuthTokenParser;

	/**
	* @var \OCP\IGroupManager
	*/
	private $groupManager;
	private $logger;

	public function __construct(
		$AppName,
		\OCP\IRequest $request,
		\OCP\IConfig $config,
		\OCP\IUserSession $session,
		\OCP\IUserManager $userManager,
		\OCA\JwtAuth\Helper\LoginChain $loginChain,
		\OCA\JwtAuth\Helper\JwtAuthTokenParser $jwtAuthTokenParser,
		\OCP\IGroupManager $groupManager,
		\Psr\Log\LoggerInterface $logger
	) {
		parent::__construct($AppName, $request);

		$this->config = $config;
		$this->session = $session;
		$this->userManager = $userManager;
		$this->loginChain = $loginChain;
		$this->jwtAuthTokenParser = $jwtAuthTokenParser;
		$this->groupManager = $groupManager;
		$this->logger = $logger;
	}

	/**
	 * @NoAdminRequired
	 * @NoCSRFRequired
	 * @PublicPage
	 */
	public function auth(string $token, string $targetPath) {
		$payload = $this->jwtAuthTokenParser->parseValidatedToken($token);
		$username = $payload['preferred_username'];

		$redirectUrl = '/';
		$targetPathParsed = parse_url($targetPath);
		if ($targetPathParsed !== false) {
			$redirectUrl = $targetPathParsed['path'];
		}

		$user = $this->userManager->get($username);

		if ($user === null) {
			//create user
			$userPassword = substr(base64_encode(random_bytes(64)), 0, 30);
			$user = $this->userManager->createUser($username, $userPassword);
			$this->config->setUserValue($username, $this->appName, 'disable_password_confirmation', 1);
			$user->setDisplayName($payload['name']);
			if (method_exists($user, 'setSystemEMailAddress')) {
				$user->setSystemEMailAddress((string)$payload['email']);
			} else {
				$user->setEMailAddress((string)$payload['email']);
			}
		}
		$claim = $this->config->getSystemConfig()->getValue('jwtauth')['GroupsClaim'];
		if(isset($claim)) {
			$roles = $this->config->getSystemConfig()->getValue('jwtauth')['Roles'];
			$tokenRoles = explode(',', $payload[$claim]);
			if(!is_array($tokenRoles)) {
				$tokenRoles = array($payload[$claim]);
			}
			$groups = array_intersect($roles, $tokenRoles);
			//remove all group of user to add after
			$userGroups = $this->groupManager->getUserGroups($user);
			foreach($userGroups as $uG) {
				$uG->removeUser($user);
			}
			//create group if not exist, add user to group
			foreach($groups as $value) {
				if (!$this->groupManager->groupExists($value)) {
					$newGroup = $this->groupManager->createGroup($value);
					$newGroup->addUser($user);
				} else {
					$newGroup = $this->groupManager->get($value);
					$newGroup->addUser($user);
				}
			}
		}

		if ($this->session->getUser() === $user) {
			// Already logged in. No need to log in once again.
			return new RedirectResponse($redirectUrl);
		}

		if ($this->session->getUser() !== null) {
			// If there is an old session, it would cause our login attempt to not work.
			// We'd be setting some session cookies, but other old ones would remain
			// and the old session would be in use.
			//
			// We work around this by destroying the old session before proceeding.
			$this->session->logout();
		}

		$loginData = new \OC\Authentication\Login\LoginData(
			$this->request,
			$username,
			// Password. It doesn't matter because our custom Login chain
			// doesn't validate it at all.
			'',
			$redirectUrl,
			'', // Timezone
			'', // Timezone offset
		);

		// Prepopulate the login request with the user we're logging in.
		// This usually happens in one of the steps of the default LoginChain.
		// For our custom login chain, we pre-populate it.
		$loginData->setUser($user);

		// This is expected to log the user in, updating the session, etc.
		$result = $this->loginChain->process($loginData);
		if (!$result->isSuccess()) {
			// We don't expect any failures, but who knows..
			die('Internal login failure');
		}

		return new RedirectResponse($redirectUrl);
	}

}
