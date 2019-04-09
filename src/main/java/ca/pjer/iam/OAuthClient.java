package ca.pjer.iam;

import java.net.URI;
import java.util.Map;

public interface OAuthClient {

    URI getAuthorizeUri(URI redirectUri, String state);

    Map<String, Object> getTokens(URI redirectUri, String code);

}
