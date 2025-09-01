<?php

namespace OauthJwtService\Jwt;

use Illuminate\Support\ServiceProvider;

class OauthJWTServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any package services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../../config/oauthJWT.php' => config_path('oauthJWT.php'),
        ], 'config');

        $this->ensureKeysExist();
    }

    protected function ensureKeysExist()
    {
        $keyPath = storage_path('oauth-keys/oauth-private.key');
        $dir = dirname($keyPath);

        // Create directory if it doesn't exist
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        // Generate private key if it doesn't exist
        if (!file_exists($keyPath)) {
            $res = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            openssl_pkey_export($res, $privateKey);
            file_put_contents($keyPath, $privateKey);

            // Optional: generate public key
            $pubKeyPath = storage_path('oauth-keys/oauth-public.key');
            $pubKey = openssl_pkey_get_details($res)['key'];
            file_put_contents($pubKeyPath, $pubKey);
        }
    }

}
