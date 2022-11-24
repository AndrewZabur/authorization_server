package oauth2.service.authorization;

import lombok.RequiredArgsConstructor;
import oauth2.converter.AuthorizationConsentConverter;
import oauth2.model.AuthorizationConsent;
import oauth2.repository.AuthorizationConsentRepository;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@RequiredArgsConstructor
public class AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final AuthorizationConsentConverter authorizationConsentConverter;
    private final AuthorizationConsentRepository authorizationConsentRepository;

    @Transactional
    @Override
    public void save(OAuth2AuthorizationConsent oauth2AuthorizationConsent) {
        AuthorizationConsent authorizationConsent = authorizationConsentConverter.convertTo(oauth2AuthorizationConsent);
        this.authorizationConsentRepository.save(authorizationConsent);
    }

    @Transactional
    @Override
    public void remove(OAuth2AuthorizationConsent oauth2AuthorizationConsent) {
        this.authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
                oauth2AuthorizationConsent.getRegisteredClientId(), oauth2AuthorizationConsent.getPrincipalName());
    }

    @Transactional
    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        AuthorizationConsent authorizationConsent =
                this.authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName);
        if (authorizationConsent != null) {
            return authorizationConsentConverter.convertFrom(authorizationConsent);
        }
        return null;
    }

}
