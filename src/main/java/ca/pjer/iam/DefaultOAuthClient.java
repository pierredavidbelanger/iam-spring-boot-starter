package ca.pjer.iam;

import ca.pjer.iam.config.OAuthClientProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

public class DefaultOAuthClient implements OAuthClient {

    private OAuthClientProperties properties;
    private final RestTemplate restTemplate;

    public DefaultOAuthClient(OAuthClientProperties properties, RestTemplateBuilder restTemplateBuilder) {
        this.properties = properties;
        restTemplate = restTemplateBuilder.build();
    }

    public URI getAuthorizeUri(URI redirectUri, String state) {
        return UriComponentsBuilder.fromUriString(properties.getAuthorizeUri())
                .queryParam("response_type", "code")
                .queryParam("client_id", properties.getClientId())
                .queryParam("redirect_uri", redirectUri.toString())
                .queryParam("state", state)
                .build().toUri();
    }

    @Override
    public URI getLogoutUri(URI redirectUri) {
        return UriComponentsBuilder.fromUriString(properties.getLogoutUri())
                .queryParam("client_id", properties.getClientId())
                .queryParam(properties.getLogoutRedirectParam(), redirectUri.toString())
                .build().toUri();
    }

    public Map<String, Object> getTokens(URI redirectUri, String code) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.set("grant_type", "authorization_code");
        body.set("code", code);
        body.set("redirect_uri", redirectUri.toString());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(properties.getClientId(), properties.getClientSecret());
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);
        //noinspection rawtypes
        ResponseEntity<Map> responseEntity = restTemplate.postForEntity(URI.create(properties.getTokenUri()), requestEntity, Map.class);
        //noinspection unchecked
        return responseEntity.getBody();
    }

    @Override
    public Map<String, Object> getUserInfo(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        //noinspection rawtypes
        ResponseEntity<Map> responseEntity = restTemplate.exchange(URI.create(properties.getUserInfoUri()), HttpMethod.GET, requestEntity, Map.class);
        //noinspection unchecked
        return responseEntity.getBody();
    }
}
