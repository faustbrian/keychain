<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Conductors;

use Cline\Ancestry\Facades\Ancestry;
use Cline\Bearer\BearerManager;
use Cline\Bearer\Contracts\HasApiTokens;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\Exceptions\CannotDeriveTokenException;
use Cline\Bearer\Exceptions\InvalidDerivedAbilitiesException;
use Cline\Bearer\Exceptions\InvalidDerivedExpirationException;
use Cline\Bearer\Exceptions\InvalidTokenableException;
use Cline\Bearer\Exceptions\MissingTokenableException;
use Cline\Bearer\NewAccessToken;
use DateTimeInterface;
use Illuminate\Support\Facades\Config;

use function now;
use function throw_if;
use function throw_unless;

/**
 * Conductor for deriving child tokens from parent tokens.
 *
 * Enables hierarchical token creation where child tokens inherit restrictions
 * from their parents but can have more limited abilities and shorter lifespans.
 * This is useful for reseller scenarios where master tokens can issue customer
 * tokens without those customers needing full accounts.
 *
 * Example usage:
 * ```php
 * // Reseller creates master token
 * $resellerMaster = Bearer::for($reseller)->issue('sk', 'Reseller Master');
 *
 * // Derive customer token
 * $customerToken = Bearer::derive($resellerMaster->accessToken)
 *     ->abilities(['invoices:read', 'webhooks:receive'])
 *     ->metadata(['reseller_customer_id' => 'cust_xyz'])
 *     ->expiresAt(now()->addYear())
 *     ->as('Customer XYZ Key');
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TokenDerivationConductor
{
    /**
     * Create a new token derivation conductor instance.
     *
     * @param BearerManager          $manager         core bearer manager instance providing
     *                                                access to token generation, hashing, and
     *                                                audit functionality
     * @param AccessToken            $parentToken     The parent token from which the child token
     *                                                will be derived. Child tokens inherit type,
     *                                                environment, and restrictions from this parent.
     * @param array<int, string>     $abilities       Token abilities for the derived token. Must
     *                                                be a subset of the parent token's abilities
     *                                                or validation will fail during derivation.
     * @param null|DateTimeInterface $expiresAt       Optional expiration timestamp for the derived
     *                                                token. If provided, must not exceed the parent
     *                                                token's expiration or validation will fail.
     * @param array<string, mixed>   $derivedMetadata derivation-specific metadata containing
     *                                                contextual information such as reseller ID,
     *                                                customer information, or delegation details
     */
    public function __construct(
        private BearerManager $manager,
        private AccessToken $parentToken,
        private array $abilities = [],
        private ?DateTimeInterface $expiresAt = null,
        private array $derivedMetadata = [],
    ) {}

    /**
     * Set abilities for the derived token (must be subset of parent abilities).
     *
     * @param  array<int, string> $abilities Token abilities to assign
     * @return self               New conductor instance with abilities configured
     */
    public function abilities(array $abilities): self
    {
        return new self(
            $this->manager,
            $this->parentToken,
            $abilities,
            $this->expiresAt,
            $this->derivedMetadata,
        );
    }

    /**
     * Set expiration timestamp for the derived token (must be <= parent expiration).
     *
     * @param  null|DateTimeInterface $expiresAt Expiration timestamp
     * @return self                   New conductor instance with expiration configured
     */
    public function expiresAt(?DateTimeInterface $expiresAt): self
    {
        return new self(
            $this->manager,
            $this->parentToken,
            $this->abilities,
            $expiresAt,
            $this->derivedMetadata,
        );
    }

    /**
     * Set expiration in seconds from now for the derived token.
     *
     * @param  int  $seconds Seconds until expiration
     * @return self New conductor instance with expiration configured
     */
    public function expiresIn(int $seconds): self
    {
        return $this->expiresAt(now()->addSeconds($seconds));
    }

    /**
     * Set derivation-specific metadata (reseller context, customer info, etc.).
     *
     * @param  array<string, mixed> $derivedMetadata Derivation metadata
     * @return self                 New conductor instance with metadata configured
     */
    public function metadata(array $derivedMetadata): self
    {
        return new self(
            $this->manager,
            $this->parentToken,
            $this->abilities,
            $this->expiresAt,
            $derivedMetadata,
        );
    }

    /**
     * Create the derived child token with the specified name.
     *
     * Creates a new token that inherits restrictions from the parent but can have
     * more limited abilities and shorter expiration. The child token is linked to
     * the parent via the Ancestry hierarchy system.
     *
     * @param string $name Human-readable token name
     *
     * @throws CannotDeriveTokenException        If parent token cannot derive children
     * @throws InvalidDerivedAbilitiesException  If abilities are not a subset of parent
     * @throws InvalidDerivedExpirationException If expiration is beyond parent expiration
     *
     * @return NewAccessToken Container with persisted token and plain-text value
     */
    public function as(string $name): NewAccessToken
    {
        // Validate parent can derive
        if (!$this->parentToken->canDeriveTokens()) {
            throw CannotDeriveTokenException::fromParentToken($this->parentToken);
        }

        // Validate abilities subset
        if (!AccessToken::areAbilitiesSubset($this->abilities, $this->parentToken->abilities)) {
            throw InvalidDerivedAbilitiesException::create($this->abilities, $this->parentToken->abilities);
        }

        // Validate expiration
        if ($this->expiresAt instanceof DateTimeInterface && $this->parentToken->expires_at && $this->expiresAt > $this->parentToken->expires_at) {
            throw InvalidDerivedExpirationException::create($this->expiresAt, $this->parentToken->expires_at);
        }

        // Generate token using parent's type/environment
        $generator = $this->manager->tokenGenerator();
        $hasher = $this->manager->tokenHasher();
        $tokenType = $this->manager->tokenType($this->parentToken->type);

        $plainTextToken = $generator->generate(
            $tokenType->prefix(),
            $this->parentToken->environment,
        );

        // Create token with inherited restrictions
        $tokenable = $this->parentToken->tokenable;

        throw_if($tokenable === null, MissingTokenableException::forParentToken());

        throw_unless($tokenable instanceof HasApiTokens, InvalidTokenableException::mustImplementHasApiTokens());

        /** @var AccessToken $derivedToken */
        $derivedToken = $tokenable->tokens()->create([
            'type' => $this->parentToken->type,
            'environment' => $this->parentToken->environment,
            'name' => $name,
            'token' => $hasher->hash($plainTextToken),
            'prefix' => $tokenType->prefix(),
            'abilities' => $this->abilities,
            'metadata' => $this->parentToken->metadata,
            'derived_metadata' => $this->derivedMetadata,
            'allowed_ips' => $this->parentToken->allowed_ips,
            'allowed_domains' => $this->parentToken->allowed_domains,
            'rate_limit_per_minute' => $this->parentToken->rate_limit_per_minute,
            'expires_at' => $this->expiresAt ?? $this->parentToken->expires_at,
        ]);

        // Add to hierarchy using Ancestry
        /** @var string $hierarchyType */
        $hierarchyType = Config::get('bearer.derivation.hierarchy_type', 'token_derivation');
        Ancestry::addToAncestry($derivedToken, $hierarchyType, $this->parentToken);

        // Audit log
        $this->manager->auditDriver()->log($derivedToken, AuditEvent::Derived, [
            'parent_token_id' => $this->parentToken->id,
            'depth' => $derivedToken->getAncestryDepth($hierarchyType),
        ]);

        return new NewAccessToken($derivedToken, $plainTextToken);
    }
}
