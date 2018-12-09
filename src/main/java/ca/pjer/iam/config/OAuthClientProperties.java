package ca.pjer.iam.config;

import lombok.Data;

@Data
public class OAuthClientProperties {
    private String clientId;
    private String clientSecret;
    private String authorizeUri;
    private String tokenUri;
}
