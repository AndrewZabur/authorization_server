package oauth2.service.authorization;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import oauth2.converter.AuthorizationDetailsConverter;
import oauth2.model.AuthorizationDetails;
import oauth2.repository.AuthorizationDetailsRepository;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthorizationDetailsService implements OAuth2AuthorizationService {

    private final AuthorizationDetailsConverter authorizationDetailsConverter;
    private final AuthorizationDetailsRepository authorizationRepository;
    private final RegisteredClientRepository registeredClientRepository;

    @Transactional
    @Override
    public void save(OAuth2Authorization oauth2Authorization) {
        AuthorizationDetails authorizationDetails = authorizationDetailsConverter.convertTo(oauth2Authorization);
        this.authorizationRepository.save(authorizationDetails);
    }

    @Transactional
    @Override
    public void remove(OAuth2Authorization oauth2Authorization) {
        this.authorizationRepository.deleteById(oauth2Authorization.getId());
    }

    @Transactional
    @Override
    public OAuth2Authorization findById(String id) {
        Optional<AuthorizationDetails> optionalAuthorizationDetails = this.authorizationRepository.findById(id);
        if (optionalAuthorizationDetails.isPresent()) {
            AuthorizationDetails authorizationDetails = optionalAuthorizationDetails.get();
            RegisteredClient registeredClient = this.registeredClientRepository.findById(authorizationDetails.getRegisteredClientId());
            return this.authorizationDetailsConverter.convertTo(authorizationDetails, registeredClient);
        }
       return null;
    }

    @Transactional
    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        AuthorizationDetails authorizationDetails;

        if (tokenType == null) {
            authorizationDetails =
                    this.authorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValue(token);
            RegisteredClient registeredClient = this.registeredClientRepository.findById(authorizationDetails.getRegisteredClientId());
            return this.authorizationDetailsConverter.convertTo(authorizationDetails, registeredClient);
        }

        authorizationDetails = switch (tokenType.getValue()) {
            case OAuth2ParameterNames.STATE -> this.authorizationRepository.findByState(token);
            case OAuth2ParameterNames.CODE -> this.authorizationRepository.findByAuthorizationCodeValue(token);
            case OAuth2ParameterNames.ACCESS_TOKEN -> this.authorizationRepository.findByAccessTokenValue(token);
            case OAuth2ParameterNames.REFRESH_TOKEN -> this.authorizationRepository.findByRefreshTokenValue(token);
            default -> null;
        };

        if (authorizationDetails != null) {
            RegisteredClient registeredClient = this.registeredClientRepository.findById(authorizationDetails.getRegisteredClientId());
            return this.authorizationDetailsConverter.convertTo(authorizationDetails, registeredClient);
        }

        return null;
    }

}