package oauth2.repository;

import oauth2.model.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserAccount, Long> {

    UserAccount findByUsername(String username);

    boolean existsByUsername(String username);
}
