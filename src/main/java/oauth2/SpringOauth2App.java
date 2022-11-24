package oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
public class SpringOauth2App {

    public static void main(String[] args) {
        SpringApplication.run(SpringOauth2App.class, args);
    }

}
