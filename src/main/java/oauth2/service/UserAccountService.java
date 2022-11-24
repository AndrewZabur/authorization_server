package oauth2.service;

import oauth2.dto.UserRegistrationDto;
import oauth2.model.UserAccount;

public interface UserAccountService {

    UserAccount register(UserRegistrationDto registration);


}
