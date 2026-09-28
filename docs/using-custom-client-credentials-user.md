# Using custom client credentials user

By default, access tokens issued with the `client_credentials` grant authenticate as
`ClientCredentialsUser`. To provide your own user class, implement
`League\Bundle\OAuth2ServerBundle\Security\User\ClientCredentialsUserFactoryInterface` in a
service. Its `createUser(string $clientId): UserInterface` method receives the client ID
and must return the user to authenticate. Replace the default factory in your Symfony
service configuration:

```yaml
# config/services.yaml
services:
  league.oauth2_server.client_credentials_user_factory:
    class: App\Security\ClientCredentialsUserFactory
    autowire: true
```

The custom factory is used by every `oauth2` firewall. Tokens associated with a user
continue to be resolved through the configured user provider.