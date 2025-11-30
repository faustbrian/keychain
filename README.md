[![GitHub Workflow Status][ico-tests]][link-tests]
[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Total Downloads][ico-downloads]][link-downloads]

------

Stripe-style typed API tokens with groups, environments, and audit logging for Laravel. Features conductor-based API, token rotation, revocation strategies, and seamless Sanctum integration.

## Requirements

> **Requires [PHP 8.4+](https://php.net/releases/)** and Laravel 11+

## Installation

```bash
composer require cline/bearer
```

## Documentation

- **[Getting Started](cookbook/getting-started.md)** - Installation, configuration, and first steps
- **[Basic Usage](cookbook/basic-usage.md)** - Creating, validating, and managing tokens
- **[Authentication](cookbook/authentication.md)** - Integrating with Laravel authentication
- **[Custom Token Types](cookbook/custom-token-types.md)** - Defining typed tokens with abilities
- **[Token Metadata](cookbook/token-metadata.md)** - Attaching and querying token metadata
- **[Derived Keys](cookbook/derived-keys.md)** - Hierarchical token derivation for resellers
- **[Revocation & Rotation](cookbook/revocation-rotation.md)** - Token lifecycle management
- **[IP & Domain Restrictions](cookbook/ip-domain-restrictions.md)** - Network-based access control
- **[Rate Limiting](cookbook/rate-limiting.md)** - Throttling token usage
- **[Usage Tracking](cookbook/usage-tracking.md)** - Monitoring token activity
- **[Audit Logging](cookbook/audit-logging.md)** - Recording token events
- **[Token Generators](cookbook/token-generators.md)** - Custom token generation strategies

## Change log

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) and [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) for details.

## Security

If you discover any security related issues, please use the [GitHub security reporting form][link-security] rather than the issue queue.

## Credits

- [Brian Faust][link-maintainer]
- [All Contributors][link-contributors]

## License

The MIT License. Please see [License File](LICENSE.md) for more information.

[ico-tests]: https://github.com/faustbrian/bearer/actions/workflows/quality-assurance.yaml/badge.svg
[ico-version]: https://img.shields.io/packagist/v/cline/bearer.svg
[ico-license]: https://img.shields.io/badge/License-MIT-green.svg
[ico-downloads]: https://img.shields.io/packagist/dt/cline/bearer.svg

[link-tests]: https://github.com/faustbrian/bearer/actions
[link-packagist]: https://packagist.org/packages/cline/bearer
[link-downloads]: https://packagist.org/packages/cline/bearer
[link-security]: https://github.com/faustbrian/bearer/security
[link-maintainer]: https://github.com/faustbrian
[link-contributors]: ../../contributors
