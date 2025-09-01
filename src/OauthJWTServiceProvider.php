<?php

namespace OauthJwtService\Jwt;

use Illuminate\Support\ServiceProvider;
use OauthJwtService\Jwt\Services\JwtService;

class OauthJWTServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any package services.
     */
    public function boot(): void
    {
        // Publish config
        $this->publishes([
            __DIR__.'/../../config/oauthJWT.php' => config_path('oauthJWT.php'),
        ], 'config');

        // Ensure keys exist
        $this->ensureKeysExist();
    }

    /**
     * Register bindings and merge config
     */
    public function register(): void
    {
        // Merge default config so package works even if host app doesn't publish it
        $this->mergeConfigFrom(
            __DIR__.'/../../config/oauthJWT.php',
            'oauthJWT'
        );

        // Bind JwtService to container
        $this->app->singleton('oauthjwt', function ($app) {
            $privateKeyPath = config('oauthJWT.private_key_path');

            if (!file_exists($privateKeyPath)) {
                throw new \RuntimeException("Private key not found at: $privateKeyPath");
            }

            $privateKey = file_get_contents($privateKeyPath);

            return new JwtService($privateKey);
        });
    }

    /**
     * Ensure OAuth keys exist in storage
     */
    protected function ensureKeysExist()
    {
        $keyPath = storage_path('oauth-keys/oauth-private.key');
        $dir = dirname($keyPath);

        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        if (!file_exists($keyPath)) {
            $res = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            openssl_pkey_export($res, $privateKey);
            file_put_contents($keyPath, $privateKey);

            $pubKeyPath = storage_path('oauth-keys/oauth-public.key');
            $pubKey = openssl_pkey_get_details($res)['key'];
            file_put_contents($pubKeyPath, $pubKey);
        }
    }
}
