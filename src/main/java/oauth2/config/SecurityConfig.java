package oauth2.config;

import oauth2.handler.FederatedIdentityAuthenticationSuccessHandler;
import oauth2.handler.FormLoginAuthenticationSuccessHandler;
import oauth2.service.impl.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           FormLoginAuthenticationSuccessHandler formLoginAuthenticationSuccessHandler,
                                           FederatedIdentityAuthenticationSuccessHandler federatedIdentityAuthenticationSuccessHandler) throws Exception {
        http
            .authorizeHttpRequests(auth -> {
                auth.requestMatchers("/logout", "/signUp", "/login").permitAll();
                auth.anyRequest().authenticated();
            })
            .csrf(csrf -> csrf.ignoringRequestMatchers("/signUp", "/logout"))
            .formLogin(formLogin -> formLogin.successHandler(formLoginAuthenticationSuccessHandler))
            .oauth2Login(oauth2Login -> oauth2Login.successHandler(federatedIdentityAuthenticationSuccessHandler))
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(PasswordEncoder passwordEncoder,
                                                            CustomUserDetailsService customUserDetailsService) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        authenticationProvider.setUserDetailsService(customUserDetailsService);
        return authenticationProvider;
    }

    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

}
