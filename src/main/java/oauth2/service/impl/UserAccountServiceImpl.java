package oauth2.service.impl;

import lombok.RequiredArgsConstructor;
import oauth2.dto.UserRegistrationDto;
import oauth2.model.UserAccount;
import oauth2.repository.UserRepository;
import oauth2.service.UserAccountService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserAccountServiceImpl implements UserAccountService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserAccount register(UserRegistrationDto registration) {
        String encodedPassword = passwordEncoder.encode(registration.getPassword());

        UserAccount userAccount = UserAccount.builder()
                .username(registration.getUsername())
                .password(encodedPassword)
                .authorities(registration.getAuthorities())
                .name(registration.getName())
                .build();

        return userRepository.save(userAccount);
    }
}
