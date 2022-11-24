package oauth2.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class MetadataConverter {

    @Autowired
    @Qualifier("metadataObjectMapper")
    private ObjectMapper mapper;

    public Map<String, Object> metadataToMap(String metadata) {
        try {
            return this.mapper.readValue(metadata, new TypeReference<Map<String, Object>>() {});
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    public String metadataToString(Map<String, Object> metadata) {
        try {
            return this.mapper.writeValueAsString(metadata);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

}
