<?php
declare(strict_types=1);

namespace OCA\JwtAuth\Service;

use OC\Authentication\Token\DefaultTokenProvider;
use OC\User\LoginException;
use OCP\IGroupManager;
use OCP\ISession;
use OCP\IUserManager;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IURLGenerator;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Psr\Log\LoggerInterface;

class LoginService
{
    /** @var string */
    private $appName;

    /** @var IUserManager */
    private $userManager;

    /** @var IGroupManager */
    private $groupManager;

    /** @var ISession */
    private $session;

	/** @var ITimeFactory */
	private $time;

	/** @var OCP\IURLGenerator */
	private $urlGenerator;

	/** @var \Psr\Log\LoggerInterface */
	private $logger;

    public function __construct(
        $appName,
        IUserManager $userManager,
        IGroupManager $groupManager,
        ISession $session,
		ITimeFactory $time,
		IURLGenerator $urlGenerator,
		LoggerInterface $logger
    ) {
        $this->appName = $appName;
        $this->userManager = $userManager;
        $this->groupManager = $groupManager;
        $this->session = $session;
		$this->time = $time;
		$this->urlGenerator = $urlGenerator;
		$this->logger = $logger;
    }

	private function getSystemConfig(\OCP\IConfig $config, string $configValue, string $key, string $message): mixed {
		$value = $config->getSystemConfig()->getValue($configValue)[$key];
		if(!isset($value)) {
			throw new LoginException('You must provide a configuration system '.$configValue.'[\''.$key.'\'] for '.$message);
		}
		return $value;
	}

	private function parseValidatedToken(\OCP\IConfig $config, \OCP\IRequest $request): array {
		$header = $this->getSystemConfig($config, 'jwtauth', 'RequestHeader', 'the name of the request header containing the token.');
		$token = $request->getHeader($header);
		$this->logger->debug("token value: $token");
		if (!isset($token)) {
			throw new UnexpectedValueException("$header must contain a token.");
		}
		$url = $this->getSystemConfig($config, 'jwtauth', 'JWKUrl', 'url of jks endpoint.');
		$json = file_get_contents($url);
		if($json === false) {
			throw new LoginException('Public key not found.');
		}
		$json_data = json_decode($json, $assoc = true, $depth = 512, JSON_THROW_ON_ERROR);
		$decoded = JWT::decode($token, JWK::parseKeySet($json_data));
		$payload = json_decode(json_encode($decoded), $assoc = true, $depth = 512, JSON_THROW_ON_ERROR);
		$usernameClaim = $this->getSystemConfig($config, 'jwtauth', 'UsernameClaim', 'the name of username claim in token.');
		if (!array_key_exists($usernameClaim, $payload)) {
			throw new LoginException("Payload must contain $usernameClaim key.");
		}
		return $payload;
	}

	public function loginUser(\OCP\IConfig $config, \OCP\IUserSession $userSession, \OCP\IRequest $request): RedirectResponse {
		$logoutUrl = $this->getSystemConfig($config, 'jwtauth', 'LogoutConfirmationUri', 'logout uri.');
		$this->session->set('logout_url', $logoutUrl);
		$this->session->set('last-password-confirm', $this->time->getTime());
		$payload = $this->parseValidatedToken($config, $request);
		$usernameClaim = $this->getSystemConfig($config, 'jwtauth', 'UsernameClaim', 'the name of username claim in token.');
		$username = $payload[$usernameClaim];
		$user = $this->userManager->get($username);
		if ($user === null) {
			$newUser = $this->createUser($username, $config);
			$user = $newUser[0];
			$userPassword = $newUser[1];
		}
		$user = $this->manageUserInfos($user, $config, $payload);
		$groups = $this->manageGroups($config, $user, $payload);
		if(!isset($userPassword)) {
			$userPassword = substr(base64_encode(random_bytes(64)), 0, 30);
			$passwordSet = $user->setPassword($userPassword);
		}
		$this->logger->debug('connection of user: '.$user->getUID());
		if ($userSession->isLoggedIn() && $userSession->getUser()->getUID() == $user->getUID()) {
			$this->logger->debug("user in session: ".$userSession->getUser()->getUID().", user in token: ".$user->getUID().", session already exist, login.");
			return new RedirectResponse($this->urlGenerator->getAbsoluteURL('/'));
		}
		if($userSession->getUser() !== null && $userSession->getUser()->getUID() != $user->getUID()) {
			$this->logger->debug('user in session: '.$userSession->getUser()->getUID().', user in token: '.$user->getUID().', not the same user, logout of session.');
			$userSession->logout();
		}
		$this->logger->debug('creation of user session.');
		$this->completeLogin($user, $userPassword, $userSession, $request);
		return new RedirectResponse($this->urlGenerator->getAbsoluteURL('/'));
	}

	private function manageGroups(\OCP\IConfig $config, \OCP\IUser $user, array $payload): array {
		$groupsClaim = $this->getSystemConfig($config, 'jwtauth', 'GroupsClaim', 'the name of groups claim in token.');
		$roles = $this->getSystemConfig($config, 'jwtauth', 'Roles', 'the roles present in client oidc to map in nextcloud.');
		$tokenRoles = explode(',', $payload[$groupsClaim]);
		$groups = array_intersect($roles, $tokenRoles);
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
		return $groups;
	}

	private function createUser(string $username, \OCP\IConfig $config): array {
		$userPassword = substr(base64_encode(random_bytes(64)), 0, 30);
		$user = $this->userManager->createUser($username, $userPassword);
		$config->setUserValue($username, $this->appName, 'disable_password_confirmation', 1);
		return [$user, $userPassword];
	}

	private function manageUserInfos(\OCP\IUser $user, \OCP\IConfig $config, array $payload): \OCP\IUser {
		$displaynameClaim = $this->getSystemConfig($config, 'jwtauth', 'DisplaynameClaim', 'the name of displayname claim in token.');
		$displaynameSet = $user->setDisplayName($payload[$displaynameClaim]);
		$this->logger->debug('user displayname set: '.json_encode($displaynameSet));
		$emailClaim = $this->getSystemConfig($config, 'jwtauth', 'EmailClaim', 'the name of email claim in token.');
		if (method_exists($user, 'setSystemEMailAddress')) {
			$emailSet = $user->setSystemEMailAddress((string)$payload[$emailClaim]);
		} else {
			$emailSet = $user->setEMailAddress((string)$payload[$emailClaim]);
		}
		$this->logger->debug('user email set: '.json_encode($emailSet));
		return $user;
	}

    private function completeLogin($user, $userPassword, $userSession, $request)
    {
        /* On the v1 route /remote.php/webdav, a default nextcloud backend
         * tries and fails to authenticate users, then close the session.
         * This is why this check is needed.
         * https://github.com/nextcloud/server/issues/31091
         */
        if (PHP_SESSION_ACTIVE === session_status()) {
            $userSession->getSession()->regenerateId();
        }

        $tokenProvider = \OC::$server->query(DefaultTokenProvider::class);
        $userSession->setTokenProvider($tokenProvider);
        $userSession->createSessionToken($request, $user->getUID(), $user->getUID());
        $token = $tokenProvider->getToken($userSession->getSession()->getId());

        $userSession->completeLogin($user, [
            'loginName' => $user->getUID(),
            'password' => $userPassword,
            'token' => empty($userPassword) ? $token : null,
        ], false);
    }

	public function isSameUser(\OCP\IConfig $config, \OCP\IRequest $request, \OCP\IUserSession $userSession): bool {
		$payload = $this->parseValidatedToken($config, $request);
		$usernameClaim = $this->getSystemConfig($config, 'jwtauth', 'UsernameClaim', 'the name of username claim in token.');
		$username = $payload[$usernameClaim];
		if($userSession->getUser() !== null && $userSession->getUser()->getUID() != $username) {
			$this->logger->debug('user in session: '.$userSession->getUser()->getUID().', user in token: '.$username.', not same user');
			return false;
		} else {
			$this->logger->debug('user in session: '.$userSession->getUser()->getUID().', user in token: '.$username.', same user');
			return true;
		}
	}

}
