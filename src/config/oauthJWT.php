<?php

return [
    /*
    |--------------------------------------------------------------------------
    | OAuth Private Key Path
    |--------------------------------------------------------------------------
    | Path to the private key for JWT signing. Defaults to storage/oauth-keys/oauth-private.key
    | You can override this in your host app's config or .env file.
    */
    'private_key_path' => env(
        'OAUTH_PRIVATE_KEY',
        storage_path('oauth-keys/oauth-private.key')
    )
];