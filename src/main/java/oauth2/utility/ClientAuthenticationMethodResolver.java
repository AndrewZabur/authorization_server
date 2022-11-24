package oauth2.utility;

import lombok.experimental.UtilityClass;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@UtilityClass
public class ClientAuthenticationMethodResolver {

    public ClientAuthenticationMethod resolve(String clientAuthenticationMethod) {
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        }
        if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        }
        if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.NONE;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod);
    }
}
