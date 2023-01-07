package oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class TokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            JwtClaimsSet.Builder claims = context.getClaims();
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                if (context.getPrincipal() instanceof OAuth2AuthenticationToken) {
                    OAuth2AuthenticationToken authenticationToken = context.getPrincipal();
                    claims.claim("logged_in_with", authenticationToken.getAuthorizedClientRegistrationId());
                }
                if (context.getPrincipal() instanceof UsernamePasswordAuthenticationToken) {
                    UsernamePasswordAuthenticationToken authenticationToken = context.getPrincipal();
                    claims.claim("logged_in_with", "formLogin");
                }
            }
        };
    }

}
