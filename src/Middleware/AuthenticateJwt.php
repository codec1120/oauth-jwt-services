<?php

namespace OauthJwtService\Jwt\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use App\Models\User;

class AuthenticateJwt
{
    public function handle($request, Closure $next)
    {
        $token = $request->bearerToken();
        if (! $token) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        try {
            // Get public key from OAuth service (cache for performance)
            $publicKey = cache()->remember('oauth_public_key', 3600, function () {
                $response = Http::get(config('services.oauth_public_key_api'));
                return $response->json('public_key');
            });

            // Decode + verify token
            $decoded = JWT::decode($token, new Key($publicKey, 'RS256'));

            // Load user from DB
            $user = User::find($decoded->sub);

            if (!$user) {
                return response()->json(['error' => 'User not found'], 401);
            }
            
            // Make Laravel recognize this as the current user
            Auth::setUser($user);

            $request->setUserResolver(fn () => $user);

            $request->merge([ 'user_id' =>  $user->id]);

        } catch (\Exception $e) {
            return response()->json([
                'error'   => 'Invalid Token',
                'message' => $e->getMessage()
            ], 401);
        }

        return $next($request);
    }
}
