<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Security;

use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Decorates Lexik's chain token extractor so the JWT authenticator only ever
 * claims *actual* JWTs (which always contain dots: header.payload.signature).
 *
 * Without this, lexik's JWTAuthenticator::supports() returns true for ANY
 * Bearer token — including the dotless static SERVICE_TOKEN used for M2M auth.
 * Both the JWT authenticator and ServiceTokenAuthenticator then "support" the
 * request; the JWT one runs, fails to decode the opaque service token, and its
 * 401 failure response short-circuits the authenticator chain before
 * ServiceTokenAuthenticator can succeed.
 *
 * The auth design (see authentication standard) explicitly differentiates the
 * two by "absence of dots". This extractor realises that contract: a Bearer
 * value without a dot is invisible to the JWT extractor, so JWT::supports()
 * returns false and ServiceTokenAuthenticator authenticates the M2M caller.
 */
final readonly class JwtOnlyTokenExtractor implements TokenExtractorInterface
{
    public function __construct(
        private TokenExtractorInterface $inner,
    ) {}

    public function extract(Request $request): string|false
    {
        $token = $this->inner->extract($request);

        if ($token === false) {
            return false;
        }

        // A JWT is header.payload.signature — at least two dots. An opaque
        // service token has none. Treat dotless tokens as "no JWT present".
        if (!\str_contains($token, '.')) {
            return false;
        }

        return $token;
    }
}
