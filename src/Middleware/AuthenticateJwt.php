<?php

namespace OauthJwtService\Jwt\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Redis;

class AuthenticateJwt
{
    public function handle($request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        try {
            // Get public key from OAuth service (cache for performance)
            $publicKey = cache()->remember('oauth_public_key', 3600, function () {
                $response = Http::timeout(5)->get(config('services.oauth_public_key_api'));
                return $response->json('public_key');
            });
        } catch (\Throwable $e) {
            return $this->unavailable($e);
        }

        if (!$publicKey) {
            return $this->unavailable(new \RuntimeException('OAuth public key unavailable'));
        }

        try {
            // Decode + verify token
            $decoded = JWT::decode($token, new Key($publicKey, 'RS256'));
        } catch (\UnexpectedValueException|\DomainException $e) {
            // Expired, bad signature or malformed: the only cases where the token itself is invalid
            return response()->json([
                'error'   => 'Invalid Token',
                'message' => $e->getMessage()
            ], 401);
        }

        // Infrastructure failures below must not be 401: clients treat 401 as "refresh token",
        // and a refresh mints a new sid that kicks every other in-flight request.
        try {
            // Load user from DB
            $user = User::find($decoded->sub);

            if (!$user) {
                return response()->json(['error' => 'User not found'], 401);
            }

            $tokenSessionId = $decoded->sid ?? null;
            $prefix = config('database.redis.options.prefix');
            $domain = parse_url(config('app.url'), PHP_URL_HOST);
            $sessionKey = "{$prefix}user_session:{$domain}:{$user->id}";
            $activeSessionId = Redis::get($sessionKey);

            // Key missing (Redis restart/eviction): the token is validly signed and
            // unexpired, so re-establish its session. SETNX lets a concurrent login win.
            if (!$activeSessionId && $tokenSessionId) {
                Redis::setnx($sessionKey, $tokenSessionId);
                $activeSessionId = Redis::get($sessionKey);
            }

            if (!$activeSessionId || $activeSessionId !== $tokenSessionId) {
                // Do not delete the key here: it belongs to the newer session
                // Auto Logout
                Auth::logout();

                return response()->json([
                    'code' => 'SESSION_CONFLICT',
                    'message' => 'Your account was logged in on another device.'
                ], 401);
            }

            // Make Laravel recognize this as the current user
            Auth::setUser($user);

            $request->setUserResolver(fn () => $user);

            $request->merge(['user_id' =>  $user->id, 'token' => $token, 'user_role' => $user->role]);

        } catch (\Throwable $e) {
            return $this->unavailable($e);
        }

        return $next($request);
    }

    private function unavailable(\Throwable $e)
    {
        report($e);

        return response()->json([
            'code'    => 'AUTH_UNAVAILABLE',
            'message' => 'Authentication temporarily unavailable, please retry.'
        ], 503);
    }
}
