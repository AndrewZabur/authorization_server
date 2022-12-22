package oauth2.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;



@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "authorization_consent")
public class AuthorizationConsent {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "authorization_consent_sequence")
    @SequenceGenerator(name = "authorization_consent_sequence", sequenceName = "authorization_consent_id_seq", allocationSize = 1)
    private Long id;

    @Column(name = "registered_client_id")
    private String registeredClientId;

    @Column(name = "principal_name")
    private String principalName;

    @Column(name = "authorities")
    private String authorities;
}
