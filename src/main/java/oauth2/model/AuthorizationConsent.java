package oauth2.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

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
