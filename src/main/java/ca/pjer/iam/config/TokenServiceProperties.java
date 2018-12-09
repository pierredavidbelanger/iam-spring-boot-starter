package ca.pjer.iam.config;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Data
public class TokenServiceProperties {
    private String issuer;
    private String audience;
    private final List<Map<String, Object>> jwks = new ArrayList<>();
    private String jkwsUri;
}
