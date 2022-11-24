package oauth2.repository;

import oauth2.model.AuthorizationClient;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<AuthorizationClient, String> {

    Optional<AuthorizationClient> findByClientId(String clientId);
}
