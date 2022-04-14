<?php
declare(strict_types=1);

namespace OCA\JwtAuth\Helper;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class JwtAuthTokenParser {

	/**
	 * @var string
	 */
	private $jwkUrl;

	/**
	* @var Psr\Log\LoggerInterface
	*/
	private $logger;

	public function __construct(string $jwkUrl, \Psr\Log\LoggerInterface $logger) {
		$this->jwkUrl = $jwkUrl;
		$this->logger = $logger;
	}

	public function parseValidatedToken(string $token): ?array {
		try {
			if (!isset($token)) {
				throw new UnexpectedValueException('URL must contain a token parameter.');
			}
			$json = file_get_contents($this->jwkUrl);
			if($json === false) {
				throw new UnexpectedValueException('JWK URL not found.');
			}
			$json_data = json_decode($json, $assoc = true, $depth = 512, JSON_THROW_ON_ERROR);
			$decoded = JWT::decode($token, JWK::parseKeySet($json_data));
			$payload = json_decode(json_encode($decoded), $assoc = true, $depth = 512, JSON_THROW_ON_ERROR);
			if (!array_key_exists('preferred_username', $payload)) {
				throw new UnexpectedValueException('Payload must contain "preferred_username" key.');
			}
			return $payload;
		} catch (Exception $e) {
			$this->logger->error($e);
			return null;
		}
	}

}
