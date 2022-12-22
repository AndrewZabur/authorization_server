package oauth2.repository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import oauth2.converter.AuthorizationClientConverter;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;


@RequiredArgsConstructor
public class AuthorizationClientRepository implements RegisteredClientRepository {

    private final AuthorizationClientConverter authorizationClientConverter;
    private final ClientRepository clientRepository;

    @Transactional
    @Override
    public void save(RegisteredClient registeredClient) {
        this.clientRepository.save(authorizationClientConverter.convertTo(registeredClient));
    }

    @Transactional
    @Override
    public RegisteredClient findById(String id) {
        return clientRepository.findById(id).map(authorizationClientConverter::convertFrom).orElse(null);
    }

    @Transactional
    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId).map(authorizationClientConverter::convertFrom).orElse(null);
    }
}
