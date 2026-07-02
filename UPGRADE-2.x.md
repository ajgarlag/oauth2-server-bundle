UPGRADE GUIDE
=============

FROM 1.x to 2.0
---------------

 * Add method `getName` to `ClientInterface`
 * Change config option `authorization_server.enable_password_grant` default value to `false`
 * Change config option `authorization_server.enable_implicit_grant` default value to `false`
 * Add `EventDispatcherInterface` argument to `AccessTokenRepository::__construct()`
 * The `client.allow_plaintext_secrets` option value is now ignored and plaintext client secrets are no longer supported
 * Add method `setSecret` to `ClientInterface`
