package oauth2.converter;

import lombok.RequiredArgsConstructor;
import oauth2.model.AuthorizationDetails;
import oauth2.utility.AuthorizationGrantTypeResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Component
@RequiredArgsConstructor
public class AuthorizationDetailsConverter {

    private final MetadataConverter metadataConverter;

    public AuthorizationDetails convertTo(OAuth2Authorization oauth2Authorization) {
        AuthorizationDetails.AuthorizationDetailsBuilder builder = AuthorizationDetails.builder()
                .id(oauth2Authorization.getId())
                .registeredClientId(oauth2Authorization.getRegisteredClientId())
                .principalName(oauth2Authorization.getPrincipalName())
                .authorizationGrantType(oauth2Authorization.getAuthorizationGrantType().getValue())
                .attributes(metadataConverter.metadataToString(oauth2Authorization.getAttributes()))
                .state(oauth2Authorization.getAttribute(OAuth2ParameterNames.STATE));

        setAuthorizationCodeDetails(builder, oauth2Authorization.getToken(OAuth2AuthorizationCode.class));
        setAccessTokenDetails(builder, oauth2Authorization.getToken(OAuth2AccessToken.class));
        setRefreshTokenDetails(builder, oauth2Authorization.getToken(OAuth2RefreshToken.class));
        setOidcIdTokenDetails(builder, oauth2Authorization.getToken(OidcIdToken.class));

        return builder.build();
    }

    public OAuth2Authorization convertTo(AuthorizationDetails authorizationDetails, RegisteredClient registeredClient) {

        AuthorizationGrantType authorizationGrantType =
                AuthorizationGrantTypeResolver.resolve(authorizationDetails.getAuthorizationGrantType());

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(authorizationDetails.getId())
                .principalName(authorizationDetails.getPrincipalName())
                .authorizationGrantType(authorizationGrantType)
                .attributes(attributes -> attributes.putAll(metadataConverter.metadataToMap(authorizationDetails.getAttributes())));

        if (authorizationDetails.getState() != null) {
            builder.attribute(OAuth2ParameterNames.STATE, authorizationDetails.getState());
        }

        if (authorizationDetails.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    authorizationDetails.getAuthorizationCodeValue(),
                    authorizationDetails.getAuthorizationCodeIssuedAt().atZone(ZoneOffset.UTC).toInstant(),
                    authorizationDetails.getAuthorizationCodeExpiresAt().atZone(ZoneOffset.UTC).toInstant());
            builder.token(authorizationCode, metadata -> metadata.putAll(metadataConverter.metadataToMap(authorizationDetails.getAuthorizationCodeMetadata())));
        }

        if (authorizationDetails.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    authorizationDetails.getAccessTokenValue(),
                    authorizationDetails.getAccessTokenIssuedAt().atZone(ZoneOffset.UTC).toInstant(),
                    authorizationDetails.getAccessTokenExpiresAt().atZone(ZoneOffset.UTC).toInstant(),
                    StringUtils.commaDelimitedListToSet(authorizationDetails.getAccessTokenScopes()));
            builder.token(accessToken, metadata -> metadata.putAll(metadataConverter.metadataToMap(authorizationDetails.getAccessTokenMetadata())));
        }

        if (authorizationDetails.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    authorizationDetails.getRefreshTokenValue(),
                    authorizationDetails.getRefreshTokenIssuedAt().atZone(ZoneOffset.UTC).toInstant(),
                    authorizationDetails.getRefreshTokenExpiresAt().atZone(ZoneOffset.UTC).toInstant());
            builder.token(refreshToken, metadata -> metadata.putAll(metadataConverter.metadataToMap(authorizationDetails.getRefreshTokenMetadata())));
        }

        if (authorizationDetails.getOidcIdTokenValue() != null) {
            OidcIdToken idToken = new OidcIdToken(
                    authorizationDetails.getOidcIdTokenValue(),
                    authorizationDetails.getOidcIdTokenIssuedAt().atZone(ZoneOffset.UTC).toInstant(),
                    authorizationDetails.getOidcIdTokenExpiresAt().atZone(ZoneOffset.UTC).toInstant(),
                    metadataConverter.metadataToMap(authorizationDetails.getOidcIdTokenClaims()));
            builder.token(idToken, metadata -> metadata.putAll(metadataConverter.metadataToMap(authorizationDetails.getOidcIdTokenMetadata())));
        }

        return builder.build();
    }

    private void setAuthorizationCodeDetails(AuthorizationDetails.AuthorizationDetailsBuilder builder,
                                             OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode) {
        if (authorizationCode != null) {
            builder
                    .authorizationCodeValue(authorizationCode.getToken().getTokenValue())
                    .authorizationCodeIssuedAt(convertInstantToLocalDateTime(authorizationCode.getToken().getIssuedAt()))
                    .authorizationCodeExpiresAt(convertInstantToLocalDateTime(authorizationCode.getToken().getExpiresAt()))
                    .authorizationCodeMetadata(metadataConverter.metadataToString(authorizationCode.getMetadata()));
        }
    }

    private void setAccessTokenDetails(AuthorizationDetails.AuthorizationDetailsBuilder builder,
                                       OAuth2Authorization.Token<OAuth2AccessToken> accessToken) {
        if (accessToken != null) {
            builder
                    .accessTokenValue(accessToken.getToken().getTokenValue())
                    .accessTokenIssuedAt(convertInstantToLocalDateTime(accessToken.getToken().getIssuedAt()))
                    .accessTokenExpiresAt(convertInstantToLocalDateTime(accessToken.getToken().getExpiresAt()))
                    .accessTokenMetadata(metadataConverter.metadataToString(accessToken.getMetadata()))
                    .accessTokenScopes(StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ","));
        }
    }

    private void setRefreshTokenDetails(AuthorizationDetails.AuthorizationDetailsBuilder builder,
                                        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken) {
        if (refreshToken != null) {
            builder
                    .refreshTokenValue(refreshToken.getToken().getTokenValue())
                    .refreshTokenIssuedAt(convertInstantToLocalDateTime(refreshToken.getToken().getIssuedAt()))
                    .refreshTokenExpiresAt(convertInstantToLocalDateTime(refreshToken.getToken().getExpiresAt()))
                    .refreshTokenMetadata(metadataConverter.metadataToString(refreshToken.getMetadata()));
        }
    }

    private void setOidcIdTokenDetails(AuthorizationDetails.AuthorizationDetailsBuilder builder,
                                       OAuth2Authorization.Token<OidcIdToken> oidcIdToken) {
        if (oidcIdToken != null) {
            builder
                    .oidcIdTokenValue(oidcIdToken.getToken().getTokenValue())
                    .oidcIdTokenIssuedAt(convertInstantToLocalDateTime(oidcIdToken.getToken().getIssuedAt()))
                    .oidcIdTokenExpiresAt(convertInstantToLocalDateTime(oidcIdToken.getToken().getExpiresAt()))
                    .oidcIdTokenMetadata(metadataConverter.metadataToString(oidcIdToken.getMetadata()))
                    .oidcIdTokenClaims(metadataConverter.metadataToString(oidcIdToken.getClaims()));
        }
    }

    private LocalDateTime convertInstantToLocalDateTime(Instant timestamp) {
        return LocalDateTime.ofInstant(timestamp, ZoneOffset.UTC);
    }

}
