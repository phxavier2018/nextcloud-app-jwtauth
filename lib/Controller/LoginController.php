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
	 * @var \OCP\IUserSession
	 */
	private $userSession;

	/**
	* @var \OCA\JwtAuth\Service\LoginService
	*/
	private $loginService;

	public function __construct(
		$AppName,
		\OCP\IRequest $request,
		\OCP\IConfig $config,
		\OCP\IUserSession $userSession,
		\OCA\JwtAuth\Service\LoginService $loginService
	) {
		parent::__construct($AppName, $request);

		$this->config = $config;
		$this->userSession = $userSession;
		$this->loginService = $loginService;
	}

	/**
	 * @NoAdminRequired
	 * @NoCSRFRequired
	 * @PublicPage
	 */
	public function authJwtToken() {
		try {
			return $this->loginService->loginUser($this->config, $this->userSession, $this->request);
		} catch (\Exception $e) {
			\OC_Template::printErrorPage($e->getMessage());
		}
	}

}
