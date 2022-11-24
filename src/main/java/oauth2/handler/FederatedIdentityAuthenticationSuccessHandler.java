package oauth2.handler;

import lombok.RequiredArgsConstructor;
import oauth2.model.UserAccount;
import oauth2.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class FederatedIdentityAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private static final String NAME = "name";
    private static final String EMAIL = "email";
    private static final String PICTURE = "picture";
    
    private final UserRepository userRepository;
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken) authentication;
        String email = authenticationToken.getPrincipal().getAttribute(EMAIL);
        if (!userRepository.existsByUsername(email)) {
            UserAccount userAccount = UserAccount.builder()
                    .username(email)
                    .password(UUID.randomUUID().toString())
                    .name(authenticationToken.getPrincipal().getAttribute(NAME))
                    .picture(authenticationToken.getPrincipal().getAttribute(PICTURE))
                    .registeredWith(authenticationToken.getAuthorizedClientRegistrationId())
                    .authorities(extractAuthorities(authentication.getAuthorities()))
                    .build();
            
            userRepository.save(userAccount);
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }

    private String extractAuthorities(Collection<? extends GrantedAuthority> grantedAuthorities) {
        Set<String> authorities = grantedAuthorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        return StringUtils.collectionToCommaDelimitedString(authorities);
    }
    
}
