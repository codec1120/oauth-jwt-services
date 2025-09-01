<?php
namespace OauthJwtService\Jwt\Services;

use Firebase\JWT\JWT;

class JwtService
{
    /**
     * Issue token
    */
    public static function issueToken($user)
    {
        $privateKey = app('oauthJWT.private_key_path');;

        $payload = [
            'iss' => config('app.url'),
            'sub' => $user->id,
            'email' => $user->email,
            'roles' => $user->roles ?? [],
            'iat' => time(),
            'exp' => time() + 3600
        ];

        return JWT::encode($payload, $privateKey, 'RS256');
    }

     /**
     * Refresh access token
     */
    public static function refreshAccessToken(string $refreshToken, $user)
    {
        $hashed = hash('sha256', $refreshToken);

        $stored =  $user->refreshTokens()
            ->where('token', $hashed)
            ->where('expires_at', '>', now())
            ->first();

        if (!$stored) {
            return null;
        }

        return self::issueToken($user); // issue new access + refresh
    }

    /**
     * Revoke refresh token (logout)
     */
    public static function revokeRefreshToken($user): void
    {
        $user->refreshTokens()->delete();
    }
}
