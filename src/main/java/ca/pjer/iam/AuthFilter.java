package ca.pjer.iam;

import ca.pjer.iam.config.FilterProperties;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

@Slf4j
public class AuthFilter extends HttpFilter {

    private final boolean secure;
    private final String loginPath;
    private final String loginCallbackPath;
    private final String logoutPath;
    private final String sessionName;
    private final Duration sessionDuration;

    private final OAuthClient identityOAuthClient;
    private final TokenService identityTokenService;
    private final SessionService sessionService;
    private final TokenService sessionTokenService;

    public AuthFilter(FilterProperties filterProperties, OAuthClient identityOAuthClient, TokenService identityTokenService, SessionService sessionService, TokenService sessionTokenService) {
        secure = filterProperties.isSecure();
        loginPath = filterProperties.getLoginPath();
        loginCallbackPath = filterProperties.getLoginCallbackPath();
        logoutPath = filterProperties.getLogoutPath();
        sessionName = filterProperties.getSessionName();
        sessionDuration = filterProperties.getSessionDuration();
        this.identityOAuthClient = identityOAuthClient;
        this.identityTokenService = identityTokenService;
        this.sessionService = sessionService;
        this.sessionTokenService = sessionTokenService;
    }

    @Override
    protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        try {

            if (secure && !Optional.ofNullable(getPublicUri(req).getScheme()).orElse("").equals("https")) {
                URI location = getPublicUriBuilder(req).scheme("https").build().toUri();
                redirect(res, HttpStatus.PERMANENT_REDIRECT, location);
                return;
            }

            String path = req.getRequestURI();

            if (path.equals(loginPath)) {
                URI redirectUri = buildPublicUri(req, loginCallbackPath);
                URI location = identityOAuthClient.getAuthorizeUri(redirectUri);
                redirect(res, HttpStatus.TEMPORARY_REDIRECT, location);
                return;
            }

            if (path.equals(loginCallbackPath)) {
                URI redirectUri = buildPublicUri(req, loginCallbackPath);
                String code = req.getParameter("code");
                String idToken = (String) identityOAuthClient.getTokens(redirectUri, code).get("id_token");
                Map<String, Object> identity = identityTokenService.parse(idToken);
                Map<String, Object> session = sessionService.create(identity);
                String sessionToken = sessionTokenService.create(session);
                setCookie(res, sessionName, sessionToken, secure, (int) sessionDuration.get(ChronoUnit.SECONDS));
                redirect(res, HttpStatus.TEMPORARY_REDIRECT, buildPublicUri(req, "/"));
                return;
            }

            String sessionToken = getCookie(req, sessionName);
            if (Strings.isBlank(sessionToken)) {
                String authorization = req.getHeader("Authorization");
                if (!Strings.isBlank(authorization)) {
                    String[] authorizationParts = authorization.split(" ", 2);
                    if (authorizationParts.length > 1) {
                        if (sessionName.equalsIgnoreCase(authorizationParts[0])) {
                            sessionToken = authorizationParts[1];
                        }
                    }
                }
            }
            if (Strings.isBlank(sessionToken)) {
                sessionToken = req.getParameter(sessionName);
            }
            if (Strings.isBlank(sessionToken)) {
                res.setStatus(HttpStatus.UNAUTHORIZED.value());
                return;
            }

            if (path.equals(logoutPath)) {
                try {
                    Map<String, Object> session = sessionTokenService.parse(sessionToken);
                    sessionService.remove(session);
                } catch (Exception e) {
                    // ignore
                }
                unsetCookie(res, sessionName);
                redirect(res, HttpStatus.TEMPORARY_REDIRECT, buildPublicUri(req, "/"));
                return;
            }

            Map<String, Object> session = sessionTokenService.parse(sessionToken);
            Principal principal = sessionService.load(session);
            req = new HttpServletRequestWrapperImpl(req, principal);

        } catch (Exception e) {

            log.info("Exception in auth: {}", e.toString());
            res.setStatus(HttpStatus.UNAUTHORIZED.value());
            return;
        }

        chain.doFilter(req, res);
    }

    private void redirect(HttpServletResponse res, HttpStatus status, URI location) {
        res.addHeader("Location", location.toString());
        res.setStatus(status.value());
    }

    private URI buildPublicUri(HttpServletRequest req, String path) {
        return getPublicUriBuilder(req).replacePath(path).replaceQuery("").build().toUri();
    }

    private URI getPublicUri(HttpServletRequest req) {
        return getPublicUriBuilder(req).build().toUri();
    }

    private UriComponentsBuilder getPublicUriBuilder(HttpServletRequest req) {
        return UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(req));
    }

    private void unsetCookie(HttpServletResponse response, String name) {
        setCookie(response, name, "", false, 0);
    }

    private void setCookie(HttpServletResponse response, String name, String value, boolean secure, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setSecure(secure);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    private String getCookie(HttpServletRequest request, String name) {
        return Stream.of(Optional.ofNullable(request.getCookies()).orElse(new Cookie[0]))
                .filter(cookie -> cookie.getName().equals(name))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    private static class HttpServletRequestWrapperImpl extends HttpServletRequestWrapper {

        private Principal principal;

        HttpServletRequestWrapperImpl(HttpServletRequest request, Principal principal) {
            super(request);
            this.principal = principal;
        }

        @Override
        public Principal getUserPrincipal() {
            return principal;
        }
    }
}