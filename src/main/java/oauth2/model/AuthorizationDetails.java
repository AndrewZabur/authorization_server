package oauth2.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "authorization_details")
public class AuthorizationDetails {

    @Id
    private String id;

    @Column(name = "registered_client_id")
    private String registeredClientId;

    @Column(name = "principal_name")
    private String principalName;

    @Column(name = "authorization_grant_type")
    private String authorizationGrantType;

    @Column(name = "authorized_scopes")
    private String authorizedScopes;

    @Column(name = "attributes")
    private String attributes;

    @Column(name = "state")
    private String state;

    @Column(name = "authorization_code_value", length = 1000)
    private String authorizationCodeValue;

    @Column(name = "authorization_code_issued_at")
    private LocalDateTime authorizationCodeIssuedAt;

    @Column(name = "authorization_code_expires_at")
    private LocalDateTime authorizationCodeExpiresAt;

    @Column(name = "authorization_code_metadata", length = 1000)
    private String authorizationCodeMetadata;

    @Column(length = 4000)
    private String accessTokenValue;

    private LocalDateTime accessTokenIssuedAt;

    private LocalDateTime accessTokenExpiresAt;

    @Column(length = 2000)
    private String accessTokenMetadata;

    private String accessTokenType;

    @Column(length = 1000)
    private String accessTokenScopes;

    @Column(length = 4000)
    private String refreshTokenValue;

    private LocalDateTime refreshTokenIssuedAt;

    private LocalDateTime refreshTokenExpiresAt;

    @Column(length = 2000)
    private String refreshTokenMetadata;

    @Column(length = 4000)
    private String oidcIdTokenValue;

    private LocalDateTime oidcIdTokenIssuedAt;

    private LocalDateTime oidcIdTokenExpiresAt;

    @Column(length = 2000)
    private String oidcIdTokenMetadata;

    @Column(length = 2000)
    private String oidcIdTokenClaims;

}
