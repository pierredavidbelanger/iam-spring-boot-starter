# IAM Spring Boot Starter

Spring Boot Starter for authentication and authorization.

## Getting started

### `pom.xml`

Add one dependency

```xml
<dependency>
    <groupId>ca.pjer</groupId>
    <artifactId>iam-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

Configure the filter, identity provider and session service properties:  

### `application.properties`

```properties
# what and how it should be protected
iam.filter.secure=false
iam.filter.login-path=/auth/login
iam.filter.url-patterns=/api/*

# the external identity provider to call to get a valid subject
iam.identity-client.client-id=ad398u21ijw3s9w3939
iam.identity-client.client-secret=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
iam.identity-client.authorize-uri=https://mydomain.auth.us-east-1.amazoncognito.com/oauth2/authorize
iam.identity-client.token-uri=https://mydomain.auth.us-east-1.amazoncognito.com/oauth2/token
iam.identity-token.issuer=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example
iam.identity-token.audience=ad398u21ijw3s9w3939
iam.identity-token.jkws-uri=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example/.well-known/jwks.json

# the settings to control our subject session token
iam.session-token.issuer=https://mydomain.com
iam.session-token.audience=com.mydomain.*
iam.session-token.jwks[0].kid=1234
iam.session-token.jwks[0].alg=HS256
iam.session-token.jwks[0].kty=oct
iam.session-token.jwks[0].k=AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow
```

See the [root ConfigurationProperties object](src/main/java/ca/pjer/iam/config/AuthProperties.java) to discover all the available properties.

### Usage

Just hit `http://localhost:8080/auth/login`, after login you will come back to `http://localhost:8080/` with a `Cookie: session_token xxxxx.xxxx.xxxx` header.
