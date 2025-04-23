<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2025 LibreCode coop and contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Libresign\Service;

use GuzzleHttp\Exception\GuzzleException;
use InvalidArgumentException;
use OCA\Libresign\AppInfo\Application;
use OCP\Files\IAppData;
use OCP\Files\NotFoundException;
use OCP\Files\NotPermittedException;
use OCP\Files\SimpleFS\ISimpleFolder;
use OCP\Http\Client\IClientService;
use OCP\IAppConfig;
use OCP\IL10N;
use OCP\ITempManager;

class TSAService {
	private const CONFIG_KEYS = [
		'tsa_url',
		'tsa_auth_method',
		'tsa_username',
		'tsa_password',
		'tsa_p12_password',
		'tsa_policy_oid',
		'tsa_hash_algorithm',
	];
	private const P12_FILENAME = 'tsa.p12';
	private array $errors = [];
	private ?string $cachedDummyTSQ = null;

	public function __construct(
		private IAppConfig $appConfig,
		private IAppData $appData,
		private IClientService $clientService,
		private IL10N $l10n,
		private ITempManager $tempManager,
	) {
	}

	public function save(array $data): void {
		$this->applyAuthMethodRules($data);
		$this->storeSettings($data);
	}

	public function validate(array $data): array {
		$this->errors = [];

		if (empty($data['tsa_url'])) {
			$this->errors[] = $this->l10n->t('TSA URL is required');
		} elseif (!filter_var($data['tsa_url'], FILTER_VALIDATE_URL)) {
			$this->errors[] = $this->l10n->t('Invalid TSA URL');
		} else {
			$scheme = parse_url($data['tsa_url'], PHP_URL_SCHEME);
			if ($scheme !== 'http' && $scheme !== 'https') {
				$this->errors[] = $this->l10n->t('Invalid TSA URL');
			}
		}

		if (!empty($data['tsa_policy_oid']) && !preg_match('/^\d+(\.\d+)+$/', $data['tsa_policy_oid'])) {
			$this->errors[] = $this->l10n->t('Invalid TSA Policy OID');
		}

		$validHashes = ['sha256', 'sha384', 'sha512'];
		if (!in_array($data['tsa_hash_algorithm'] ?? '', $validHashes, true)) {
			$this->errors[] = $this->l10n->t('Unsupported hash algorithm');
		}

		$this->validateAuthConfiguration($data);

		return $this->errors;
	}

	private function validateAuthConfiguration(array $data): void {
		if (!isset($data['tsa_auth_method'])) {
			return;
		}

		if ($data['tsa_auth_method'] === 'pkcs12') {
			try {
				$file = $this->getRootFolder()->getFile(self::P12_FILENAME);
				if (!$this->isP12PasswordValid($file, $data['tsa_p12_password'] ?? '')) {
					$this->errors[] = $this->l10n->t('The provided P12 password is incorrect or the file is invalid.');
				}
			} catch (NotFoundException $e) {
				$this->errors[] = $this->l10n->t('The P12 file was not found.');
			}
		} elseif ($data['tsa_auth_method'] === 'basic') {
			$this->validateBasicAuthAccess(
				$data['tsa_url'] ?? '',
				$data['tsa_username'] ?? '',
				$data['tsa_password'] ?? ''
			);
		} else {
			$this->errors[] = $this->l10n->t('Unsupported authentication method.');
		}
	}

	private function validateBasicAuthAccess(string $url, string $username, string $password): void {
		try {
			$dummyRequest = $this->generateDummyTSQ();
			if ($dummyRequest) {
				$client = $this->clientService->newClient();
				$response = $client->post($url, [
					'auth' => [$username, $password],
					'headers' => [
						'Content-Type' => 'application/timestamp-query',
						'Accept' => 'application/timestamp-reply',
					],
					'body' => $dummyRequest,
					'timeout' => 10,
				]);

				if ($response->getStatusCode() !== 200) {
					$this->errors[] = $this->l10n->t('Unable to authenticate to TSA: unexpected status code.');
				}
			}

		} catch (GuzzleException $e) {
			$this->errors[] = $this->l10n->t('Unable to authenticate to TSA: %1$s', [$e->getMessage()]);
		}
	}

	private function generateDummyTSQ(): string {
		if ($this->cachedDummyTSQ !== null) {
			return $this->cachedDummyTSQ;
		}

		$tempFile = $this->tempManager->getTemporaryFile('.txt');
		file_put_contents($tempFile, 'LibreSign Dummy');

		$tsqFile = $this->tempManager->getTemporaryFile('.tsq');
		exec('openssl ts -query -data ' . escapeshellarg($tempFile) . ' -sha256 -no_nonce -cert > ' . escapeshellarg($tsqFile) . ' 2>/dev/null');


		$tsq = file_get_contents($tsqFile);
		if (!$tsq) {
			$this->errors[] = $this->l10n->t('Could not read TSA request file at: %1$s', [$tsqFile]);
			$tsq = '';
		}

		$this->tempManager->clean();
		$this->cachedDummyTSQ = $tsq;

		return $tsq;
	}

	private function applyAuthMethodRules(array $data): void {
		if (($data['tsa_auth_method'] ?? null) === 'pkcs12') {
			$this->handlePkcs12Auth();
			return;
		}
		$this->handleNoneAuth();
	}

	private function handleNoneAuth(): void {
		$this->appConfig->deleteKey(Application::APP_ID, 'tsa_username');
		$this->appConfig->deleteKey(Application::APP_ID, 'tsa_password');
	}

	private function handlePkcs12Auth(): void {
		$this->appConfig->deleteKey(Application::APP_ID, 'tsa_username');
	}

	private function storeSettings(array $data): void {
		foreach (self::CONFIG_KEYS as $key) {
			if (isset($data[$key])) {
				$sensitive = in_array($key, ['tsa_password', 'tsa_p12_password'], true);
				$this->appConfig->setValueString(Application::APP_ID, $key, (string)$data[$key], sensitive: $sensitive);
			}
		}
	}

	public function getValue(string $key): ?string {
		if (!in_array($key, self::CONFIG_KEYS, true)) {
			throw new InvalidArgumentException("Invalid TSA setting key: $key");
		}

		return $this->appConfig->getValueString(Application::APP_ID, $key);
	}

	public function delete(): void {
		foreach (self::CONFIG_KEYS as $key) {
			$this->appConfig->deleteKey(Application::APP_ID, $key);
		}

		try {
			$this->getRootFolder()->getFile(self::P12_FILENAME)->delete();
		} catch (NotFoundException|NotPermittedException $e) {
		}
	}

	private function getRootFolder(): ISimpleFolder {
		try {
			return $this->appData->getFolder('signature');
		} catch (NotFoundException $e) {
			return $this->appData->newFolder('signature');
		}
	}

	private function isP12PasswordValid($file, string $password): bool {
		try {
			$filePath = $this->tempManager->getTemporaryFile('.p12');
			file_put_contents($filePath, $file->getContent());

			$certs = [];
			$pkcs12Content = file_get_contents($filePath);

			if (!openssl_pkcs12_read($pkcs12Content, $certs, $password)) {
				return false;
			}
		} catch (\Throwable $e) {
			return false;
		} finally {
			$this->tempManager->clean();
		}
		return isset($certs['cert']) && isset($certs['pkey']);
	}
}
