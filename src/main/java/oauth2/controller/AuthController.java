package oauth2.controller;

import lombok.RequiredArgsConstructor;
import oauth2.dto.UserRegistrationDto;
import oauth2.model.UserAccount;
import oauth2.service.UserAccountService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final UserAccountService userAccountService;

    @PostMapping("/signUp")
    public ResponseEntity<UserAccount> signUp(@RequestBody UserRegistrationDto registration) {
        UserAccount userAccount = userAccountService.register(registration);
        return ResponseEntity.ok(userAccount);
    }

    @GetMapping("/securedUrl")
    public ResponseEntity<String> getSecureInfo() {
        return ResponseEntity.ok("You received sdfsafdvery very secure INFO!");
    }
}
