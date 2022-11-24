package oauth2.converter;

import oauth2.model.AuthorizationConsent;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class AuthorizationConsentConverter {

    public AuthorizationConsent convertTo(OAuth2AuthorizationConsent oauth2AuthorizationConsent) {
       return AuthorizationConsent.builder()
                .registeredClientId(oauth2AuthorizationConsent.getRegisteredClientId())
                .principalName(oauth2AuthorizationConsent.getPrincipalName())
                .authorities(extractAuthorities(oauth2AuthorizationConsent.getAuthorities()))
                .build();
    }

    public OAuth2AuthorizationConsent convertFrom(AuthorizationConsent authorizationConsent) {
        Set<GrantedAuthority> grantedAuthorities = extractGrantedAuthorities(authorizationConsent.getAuthorities());

        OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(
                authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
        grantedAuthorities.forEach(builder::authority);

        return builder.build();
    }

    private String extractAuthorities(Set<GrantedAuthority> grantedAuthorities) {
        Set<String> authorities = grantedAuthorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        return StringUtils.collectionToCommaDelimitedString(authorities);
    }

    private Set<GrantedAuthority> extractGrantedAuthorities(String authorities) {
        if (authorities == null) {
            return Collections.emptySet();
        }
        return StringUtils.commaDelimitedListToSet(authorities).stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

}
