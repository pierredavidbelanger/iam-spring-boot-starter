package ca.pjer.iam.config;

import lombok.Data;

@Data
public class AuthProperties {
    private final FilterProperties filter = new FilterProperties();
    private final OAuthClientProperties identityClient = new OAuthClientProperties();
    private final TokenServiceProperties identityToken = new TokenServiceProperties();
    private final TokenServiceProperties sessionToken = new TokenServiceProperties();
}
