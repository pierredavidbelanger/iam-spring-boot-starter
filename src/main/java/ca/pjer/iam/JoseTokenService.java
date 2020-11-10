package ca.pjer.iam;

import ca.pjer.iam.config.TokenServiceProperties;
import org.apache.logging.log4j.util.Strings;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.JoseException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class JoseTokenService implements TokenService {

    private final String issuer;
    private final List<String> audience;
    private final Supplier<JsonWebKey> keySupplier;
    private final VerificationKeyResolver keyResolver;

    public JoseTokenService(TokenServiceProperties properties) {
        this.issuer = properties.getIssuer();
        String aud = properties.getAudience();
        if (Strings.isNotBlank(aud)) {
            String[] auds = aud.split(",");
            this.audience = new ArrayList<>(auds.length);
            for (String a : auds) {
                if (Strings.isNotBlank(a))
                    this.audience.add(a.trim());
            }
        } else {
            audience = null;
        }

        if (!properties.getJwks().isEmpty()) {
            List<JsonWebKey> jsonWebKeys = properties.getJwks().stream()
                    .map(this::createJsonWebKeyFromParams).collect(Collectors.toList());
            JsonWebKey jsonWebKey = jsonWebKeys.get(0);
            keySupplier = () -> jsonWebKey;
            keyResolver = new JwksVerificationKeyResolver(jsonWebKeys);
        } else if (!Strings.isBlank(properties.getJkwsUri())) {
            HttpsJwks httpsJwks = new HttpsJwks(properties.getJkwsUri());
            keySupplier = () -> {
                try {
                    return httpsJwks.getJsonWebKeys().get(0);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            };
            keyResolver = new HttpsJwksVerificationKeyResolver(httpsJwks);
        } else {
            keySupplier = null;
            keyResolver = null;
        }
    }

    private JsonWebKey createJsonWebKeyFromParams(Map<String, Object> params) {
        try {
            return JsonWebKey.Factory.newJwk(params);
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String create(Map<String, Object> claims) {
        if (keySupplier == null) {
            throw new UnsupportedOperationException("Cannot create token");
        }
        JsonWebKey jwk = keySupplier.get();
        if (jwk == null) {
            throw new UnsupportedOperationException("Cannot create token");
        }
        JwtClaims jwt = new JwtClaims();
        claims.forEach(jwt::setClaim);
        jwt.setIssuer(issuer);
        jwt.setIssuedAt(NumericDate.now());
        jwt.setAudience(audience);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(jwk.getKey());
        jws.setKeyIdHeaderValue(jwk.getKeyId());
        jws.setAlgorithmHeaderValue(jwk.getAlgorithm());
        jws.setPayload(jwt.toJson());
        try {
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Map<String, Object> parse(String token) {
        JwtConsumerBuilder builder = new JwtConsumerBuilder();
        builder.setRequireSubject();
        if (!Strings.isBlank(issuer)) {
            builder.setExpectedIssuer(issuer);
        }
        if (audience != null && audience.size() > 0) {
            builder.setExpectedAudience(audience.toArray(new String[]{}));
        }
        if (keyResolver != null) {
            builder.setVerificationKeyResolver(keyResolver);
        }
        JwtConsumer jwtConsumer = builder.build();
        JwtClaims jwt;
        try {
            jwt = jwtConsumer.processToClaims(token);
        } catch (InvalidJwtException e) {
            throw new RuntimeException(e);
        }
        return jwt.getClaimsMap();
    }
}
