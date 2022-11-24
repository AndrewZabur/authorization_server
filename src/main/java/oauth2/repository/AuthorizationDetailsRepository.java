package oauth2.repository;

import oauth2.model.AuthorizationDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorizationDetailsRepository extends JpaRepository<AuthorizationDetails, String> {

    AuthorizationDetails findByState(String state);
    AuthorizationDetails findByAuthorizationCodeValue(String authorizationCode);
    AuthorizationDetails findByAccessTokenValue(String accessToken);
    AuthorizationDetails findByRefreshTokenValue(String refreshToken);

    @Query("select a from AuthorizationDetails a where a.state = :token" +
            " or a.authorizationCodeValue = :token" +
            " or a.accessTokenValue = :token" +
            " or a.refreshTokenValue = :token"
    )
    AuthorizationDetails findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValue(@Param("token") String token);
}

