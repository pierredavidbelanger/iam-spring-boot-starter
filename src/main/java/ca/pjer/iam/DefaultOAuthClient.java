package ca.pjer.iam;

import ca.pjer.iam.config.OAuthClientProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

public class DefaultOAuthClient implements OAuthClient {

    private final String clientId;
    private final String clientSecret;
    private final String authorizeUri;
    private final String tokenUri;
    private final String logoutUri;
    private final RestTemplate restTemplate;

    public DefaultOAuthClient(OAuthClientProperties properties, RestTemplateBuilder restTemplateBuilder) {
        this.clientId = properties.getClientId();
        this.clientSecret = properties.getClientSecret();
        this.authorizeUri = properties.getAuthorizeUri();
        this.tokenUri = properties.getTokenUri();
        this.logoutUri = properties.getLogoutUri();
        restTemplate = restTemplateBuilder.build();
    }

    public URI getAuthorizeUri(URI redirectUri, String state) {
        return UriComponentsBuilder.fromUriString(authorizeUri)
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri.toString())
                .queryParam("state", state)
                .build().toUri();
    }

    @Override
    public URI getLogoutUri(URI redirectUri) {
        return UriComponentsBuilder.fromUriString(logoutUri)
                .queryParam("client_id", clientId)
                .queryParam("logout_uri", redirectUri.toString())
                .build().toUri();
    }

    public Map<String, Object> getTokens(URI redirectUri, String code) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.set("grant_type", "authorization_code");
        body.set("code", code);
        body.set("redirect_uri", redirectUri.toString());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(clientId, clientSecret);
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);
        ResponseEntity<Map> responseEntity = restTemplate.postForEntity(URI.create(tokenUri), requestEntity, Map.class);
        //noinspection unchecked
        return responseEntity.getBody();
    }
}
