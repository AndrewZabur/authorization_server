package oauth2.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import oauth2.service.authorization.AuthorizationDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

import java.util.List;

@Configuration
public class ObjectMapperConfig {

    @Bean
    public ObjectMapper metadataObjectMapper() {
        ClassLoader classLoader = AuthorizationDetailsService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);

        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .registerModule(new OAuth2AuthorizationServerJackson2Module())
                .registerModules(securityModules);
    }

    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule());
    }
}
