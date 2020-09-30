package ca.pjer.iam.config;

import lombok.Data;

@Data
public class OAuthClientProperties {
    private String clientId;
    private String clientSecret;
    private String authorizeUri;
    private String tokenUri;
    private String userInfoUri;
    private String logoutUri;
    // This parameter is not standard OAuth. Each provider will have his own ...
    private String logoutRedirectParam = "logout_uri";
}
