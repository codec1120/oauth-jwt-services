<?php
namespace OauthJwtService\Jwt\Services;

use Firebase\JWT\JWT;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Redis;

class JwtService
{
    /**
     * Issue token
    */
    public static function issueToken($user)
    {
        $privateKey = file_get_contents(config('oauthJWT.private_key_path'));
        $sessionId = Str::uuid()->toString();
        Redis::set("user_session:{$user->id}", $sessionId);

        $payload = [
            'iss' => config('app.url'),
            'sub' => $user->id,
            'sid' => $sessionId,
            'email' => $user->email,
            'roles' => $user->roles ?? [],
            'iat' => time(),
            'exp' => time() + 604800 // 1 week expiration
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
