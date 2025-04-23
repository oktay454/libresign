<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2025 LibreCode coop and contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Libresign\Tests\Unit\Service;

use InvalidArgumentException;
use OCA\Libresign\AppInfo\Application;
use OCA\Libresign\Service\TSAService;
use OCP\Files\IAppData;
use OCP\Http\Client\IClientService;
use OCP\IAppConfig;
use OCP\IL10N;
use OCP\ITempManager;
use OCP\L10N\IFactory as IL10NFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;

class TSAServiceTest extends \OCA\Libresign\Tests\Unit\TestCase {
	private IAppConfig $appConfig;
	private IAppData&MockObject $appData;
	private IClientService&MockObject $clientService;
	private IL10N $l10n;
	private ITempManager $tempManager;

	public function setUp(): void {
		$this->appConfig = $this->getMockAppConfig();
		$this->appData = $this->createMock(IAppData::class);
		$this->clientService = $this->createMock(IClientService::class);
		$this->l10n = \OCP\Server::get(IL10NFactory::class)->get(Application::APP_ID);
		$this->tempManager = \OCP\Server::get(ITempManager::class);
	}

	private function getClass(): TSAService {
		return new TSAService(
			$this->appConfig,
			$this->appData,
			$this->clientService,
			$this->l10n,
			$this->tempManager,
		);
	}

	#[DataProvider('providerSave')]
	public function testSave(array $input, array $expectedStored): void {
		$tsa = $this->getClass();
		$tsa->save($input);

		foreach ($expectedStored as $key => $expectedValue) {
			$this->assertSame($expectedValue, $this->appConfig->getValueString('libresign', $key));
		}
	}

	public static function providerSave(): array {
		return [
			'basic auth' => [
				[
					'tsa_url' => 'https://example.coop',
					'tsa_hash_algorithm' => 'sha256',
					'tsa_auth_method' => 'basic',
					'tsa_username' => 'user',
					'tsa_password' => 'pass',
				],
				[
					'tsa_url' => 'https://example.coop',
					'tsa_hash_algorithm' => 'sha256',
					'tsa_auth_method' => 'basic',
					'tsa_username' => 'user',
					'tsa_password' => 'pass',
				],
			],
			'pkcs12' => [
				[
					'tsa_url' => 'https://tsa.coop',
					'tsa_hash_algorithm' => 'sha512',
					'tsa_auth_method' => 'pkcs12',
					'tsa_p12_password' => 'secure',
				],
				[
					'tsa_url' => 'https://tsa.coop',
					'tsa_hash_algorithm' => 'sha512',
					'tsa_auth_method' => 'pkcs12',
					'tsa_p12_password' => 'secure',
				],
			],
			'no auth method clears auth keys' => [
				[
					'tsa_url' => 'https://without.auth',
					'tsa_hash_algorithm' => 'sha256',
				],
				[
					'tsa_url' => 'https://without.auth',
					'tsa_hash_algorithm' => 'sha256',
				],
			],
		];
	}

	#[DataProvider('providerValidate')]
	public function testValidate(array $input, array $expectedErrors): void {
		$tsa = $this->getClass();
		$errors = $tsa->validate($input);
		$this->assertEqualsCanonicalizing($expectedErrors, $errors);
	}

	public static function providerValidate(): array {
		return [
			'invalid url and hash' => [
				[
					'tsa_url' => 'notaurl',
					'tsa_hash_algorithm' => 'md5',
				],
				['Invalid TSA URL', 'Unsupported hash algorithm'],
			],
			'valid minimal' => [
				[
					'tsa_url' => 'https://example.coop/tsa',
					'tsa_hash_algorithm' => 'sha256',
				],
				[],
			],
			'invalid policy OID format' => [
				[
					'tsa_url' => 'https://tsa.example.coop',
					'tsa_hash_algorithm' => 'sha512',
					'tsa_policy_oid' => '1.2.invalid.oid',
				],
				['Invalid TSA Policy OID'],
			],
			'unsupported hash algorithm only' => [
				[
					'tsa_url' => 'https://tsa.example.coop',
					'tsa_hash_algorithm' => 'md4',
				],
				['Unsupported hash algorithm'],
			],
			'empty input' => [
				[],
				['TSA URL is required', 'Unsupported hash algorithm'],
			],
			'invalid url with valid hash and OID' => [
				[
					'tsa_url' => 'ftp://badurl',
					'tsa_hash_algorithm' => 'sha384',
					'tsa_policy_oid' => '2.5.4.3',
				],
				['Invalid TSA URL'],
			],
			'valid url and OID, invalid hash' => [
				[
					'tsa_url' => 'https://tsa.example.coop',
					'tsa_hash_algorithm' => 'sha1',
					'tsa_policy_oid' => '1.2.3.4',
				],
				['Unsupported hash algorithm'],
			],
			'valid input with policy OID' => [
				[
					'tsa_url' => 'https://tsa.example.coop',
					'tsa_hash_algorithm' => 'sha256',
					'tsa_policy_oid' => '1.2.3.4.5',
				],
				[],
			],
			'Invalid auth method' => [
				[
					'tsa_url' => 'https://tsa.example.coop',
					'tsa_hash_algorithm' => 'sha256',
					'tsa_auth_method' => 'invalid',
				],
				['Unsupported authentication method.'],
			],
			'PKCS12 file not found' => [
				[
					'tsa_url' => 'https://tsa.example.coop',
					'tsa_hash_algorithm' => 'sha256',
					'tsa_auth_method' => 'pkcs12',
					'tsa_p12_password' => 'any',
				],
				['The provided P12 password is incorrect or the file is invalid.'],
			],
		];
	}

	#[DataProvider('providerValidateBasicAuth')]
	public function testValidateBasicAuth(array $input, int $statusCode, array $expectedErrors): void {
		$client = $this->createMock(\OCP\Http\Client\IClient::class);
		$response = $this->createMock(\OCP\Http\Client\IResponse::class);
		$response->method('getStatusCode')->willReturn($statusCode);
		$client->method('post')->willReturn($response);
		$this->clientService->method('newClient')->willReturn($client);

		$tsa = $this->getClass();

		$errors = $tsa->validate($input);
		$this->assertEqualsCanonicalizing($expectedErrors, $errors);
	}

	public static function providerValidateBasicAuth(): array {
		return [
			'auth success' => [
				[
					'tsa_url' => 'https://example.coop/tsa',
					'tsa_hash_algorithm' => 'sha256',
					'tsa_auth_method' => 'basic',
					'tsa_username' => 'user',
					'tsa_password' => 'correct',
				],
				200,
				[],
			],
			'auth failure - wrong password' => [
				[
					'tsa_url' => 'https://example.coop/tsa',
					'tsa_hash_algorithm' => 'sha256',
					'tsa_auth_method' => 'basic',
					'tsa_username' => 'user',
					'tsa_password' => 'wrong',
				],
				401,
				['Unable to authenticate to TSA: unexpected status code.'],
			],
			'auth not required - no credentials' => [
				[
					'tsa_url' => 'https://example.coop/tsa',
					'tsa_hash_algorithm' => 'sha256',
					'tsa_auth_method' => 'basic',
				],
				200,
				[],
			],
		];
	}

	public function testDeleteClearsAllKeys(): void {
		$tsa = $this->getClass();
		$data = [
			'tsa_url' => 'https://example.coop',
			'tsa_hash_algorithm' => 'sha256',
			'tsa_auth_method' => 'basic',
			'tsa_username' => 'user',
			'tsa_password' => 'pass',
		];
		$tsa->save($data);

		$tsa->delete();

		$this->assertEmpty($tsa->getValue('tsa_url'));
		$this->assertEmpty($tsa->getValue('tsa_hash_algorithm'));
		$this->assertEmpty($tsa->getValue('tsa_auth_method'));
		$this->assertEmpty($tsa->getValue('tsa_username'));
		$this->assertEmpty($tsa->getValue('tsa_password'));
	}

	public function testGetValueReturnsConfiguredValue(): void {
		$tsa = $this->getClass();
		$data = [
			'tsa_url' => 'https://example.coop',
			'tsa_hash_algorithm' => 'sha256',
			'tsa_auth_method' => 'basic',
			'tsa_username' => 'user',
			'tsa_password' => 'pass',
		];
		$tsa->save($data);
		foreach ($data as $key => $expected) {
			$actual = $tsa->getValue($key);
			$this->assertSame($expected, $actual);
		}
	}

	public function testGetValueThrowsExceptionForInvalidKey(): void {
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid TSA setting key: invalid_key');
		$tsa = $this->getClass();
		$tsa->getValue('invalid_key');
	}
}
