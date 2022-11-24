package oauth2.converter;

import lombok.RequiredArgsConstructor;
import oauth2.model.AuthorizationClient;
import oauth2.utility.AuthorizationGrantTypeResolver;
import oauth2.utility.ClientAuthenticationMethodResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class AuthorizationClientConverter {

    private static final LocalDateTime CLIENT_SECRET_NEVER_EXPIRES_LDT = null;
    private static final Instant CLIENT_SECRET_NEVER_EXPIRES_INSTANT = null;
    private final MetadataConverter metadataConverter;

    public AuthorizationClient convertTo(RegisteredClient registeredClient) {
        List<String> clientAuthenticationMethods = registeredClient.getClientAuthenticationMethods().stream()
                        .map(ClientAuthenticationMethod::getValue)
                        .collect(Collectors.toList());

        List<String> authorizationGrantTypes = registeredClient.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)
                        .collect(Collectors.toList());

        return AuthorizationClient.builder()
                .id(registeredClient.getId())
                .clientId(registeredClient.getClientId())
                .clientIdIssuedAt(LocalDateTime.now())
                .clientSecret(registeredClient.getClientSecret())
                .clientSecretExpiresAt(CLIENT_SECRET_NEVER_EXPIRES_LDT)
                .clientName(registeredClient.getClientName())
                .clientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods))
                .authorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes))
                .redirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()))
                .scopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()))
                .clientSettings(metadataConverter.metadataToString(registeredClient.getClientSettings().getSettings()))
                .tokenSettings(metadataConverter.metadataToString(registeredClient.getTokenSettings().getSettings()))
                .build();
    }

    public RegisteredClient convertFrom(AuthorizationClient authorizationClient) {
        RegisteredClient.Builder builder = RegisteredClient.withId(authorizationClient.getId())
            .clientId(authorizationClient.getClientId())
            .clientIdIssuedAt(authorizationClient.getClientIdIssuedAt().atZone(ZoneOffset.UTC).toInstant())
            .clientSecret(authorizationClient.getClientSecret())
            .clientSecretExpiresAt(CLIENT_SECRET_NEVER_EXPIRES_INSTANT)
            .clientName(authorizationClient.getClientName());

        setClientAuthenticationMethods(builder, authorizationClient.getClientAuthenticationMethods());
        setAuthorizationGrantTypes(builder, authorizationClient.getAuthorizationGrantTypes());
        setRedirectUris(builder, authorizationClient.getRedirectUris());
        setScopes(builder, authorizationClient.getScopes());
        setClientSettings(builder, authorizationClient.getClientSettings());
        setTokenSettings(builder, authorizationClient.getTokenSettings());

        return builder.build();
    }

    private void setClientAuthenticationMethods(RegisteredClient.Builder builder, String clientAuthenticationMethods) {
        extractSetFromCommaSeparatedString(clientAuthenticationMethods).forEach(clientAuthenticationMethod -> {
            builder.clientAuthenticationMethod(ClientAuthenticationMethodResolver.resolve(clientAuthenticationMethod));
        });
    }

    private void setAuthorizationGrantTypes(RegisteredClient.Builder builder, String authorizationGrantTypes) {
        extractSetFromCommaSeparatedString(authorizationGrantTypes).forEach(authorizationGrantType -> {
            builder.authorizationGrantType(AuthorizationGrantTypeResolver.resolve(authorizationGrantType));
        });
    }

    private void setRedirectUris(RegisteredClient.Builder builder, String redirectUris) {
        extractSetFromCommaSeparatedString(redirectUris).forEach(builder::redirectUri);
    }

    private void setScopes(RegisteredClient.Builder builder, String scopes) {
        extractSetFromCommaSeparatedString(scopes).forEach(builder::scope);
    }

    private void setClientSettings(RegisteredClient.Builder builder, String clientSettings) {
        ClientSettings settings = ClientSettings.withSettings(metadataConverter.metadataToMap(clientSettings)).build();
        builder.clientSettings(settings);
    }

    private void setTokenSettings(RegisteredClient.Builder builder, String tokenSettings) {
        TokenSettings settings = TokenSettings.withSettings(metadataConverter.metadataToMap(tokenSettings)).build();
        builder.tokenSettings(settings);
    }

    private Set<String> extractSetFromCommaSeparatedString(String commaSeparatedValues) {
        return StringUtils.commaDelimitedListToSet(commaSeparatedValues);
    }

}

