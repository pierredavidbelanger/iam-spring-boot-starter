package ca.pjer.iam;

import java.net.URI;
import java.util.Map;

public interface OAuthClient {

    URI getAuthorizeUri(URI redirectUri, String state);

    URI getLogoutUri(URI logoutUri);

    Map<String, Object> getTokens(URI redirectUri, String code);

    Map<String, Object> getUserInfo(String accessToken);

}
