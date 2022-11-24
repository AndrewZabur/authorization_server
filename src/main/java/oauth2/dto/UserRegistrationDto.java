package oauth2.dto;

import lombok.Data;

@Data
public class UserRegistrationDto {

    private String username;
    private String password;
    private String name;
    private String picture;
    private String authorities;
    private String registeredWith;
    private Boolean firstLogin;

}
