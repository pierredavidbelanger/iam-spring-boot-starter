package ca.pjer.iam.config.auto;

import ca.pjer.iam.*;
import ca.pjer.iam.config.AuthProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@SuppressWarnings("unused")
public class AutoConfig {

    @Bean(name = "iam.authProperties")
    @ConfigurationProperties("iam")
    @ConditionalOnMissingBean(name = "iam.authProperties")
    AuthProperties authProperties() {
        return new AuthProperties();
    }

    @Bean(name = "iam.identityOAuthClient")
    @ConditionalOnMissingBean(name = "iam.identityOAuthClient")
    OAuthClient identityOAuthClient(@Autowired @Qualifier("iam.authProperties") AuthProperties properties,
                                    @Autowired RestTemplateBuilder restTemplateBuilder) {
        return new DefaultOAuthClient(properties.getIdentityClient(), restTemplateBuilder);
    }

    @Bean(name = "iam.identityTokenService")
    @ConditionalOnMissingBean(name = "iam.identityTokenService")
    TokenService identityTokenService(@Autowired @Qualifier("iam.authProperties") AuthProperties properties) {
        return new JoseTokenService(properties.getIdentityToken());
    }

    @Bean(name = "iam.sessionService")
    @ConditionalOnMissingBean(name = "iam.sessionService")
    SessionService sessionService() {
        return new DefaultSessionService();
    }

    @Bean(name = "iam.sessionTokenService")
    @ConditionalOnMissingBean(name = "iam.sessionTokenService")
    TokenService sessionTokenService(@Autowired @Qualifier("iam.authProperties") AuthProperties properties) {
        return new JoseTokenService(properties.getSessionToken());
    }

    @Bean(name = "iam.authFilter")
    @ConditionalOnMissingBean(name = "iam.authFilter")
    AuthFilter authFilter(@Autowired @Qualifier("iam.authProperties") AuthProperties properties,
                          @Autowired @Qualifier("iam.identityOAuthClient") OAuthClient identityOAuthClient,
                          @Autowired @Qualifier("iam.identityTokenService") TokenService identityTokenService,
                          @Autowired @Qualifier("iam.sessionService") SessionService sessionService,
                          @Autowired @Qualifier("iam.sessionTokenService") TokenService sessionTokenService) {
        return new AuthFilter(properties.getFilter(), identityOAuthClient, identityTokenService, sessionService, sessionTokenService);
    }

    @Bean(name = "iam.authFilterRegistrationBean")
    @ConditionalOnMissingBean(name = "iam.authFilterRegistrationBean")
    FilterRegistrationBean<AuthFilter> authFilterRegistrationBean(@Autowired @Qualifier("iam.authProperties") AuthProperties properties,
                                                                  @Autowired @Qualifier("iam.authFilter") AuthFilter authFilter) {
        FilterRegistrationBean<AuthFilter> bean = new FilterRegistrationBean<>();
        bean.setFilter(authFilter);
        bean.addUrlPatterns(properties.getFilter().getLoginPath(),
                properties.getFilter().getLoginCallbackPath(),
                properties.getFilter().getLogoutPath());
        properties.getFilter().getUrlPatterns().forEach(bean::addUrlPatterns);
        return bean;
    }
}
