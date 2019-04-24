package ca.pjer.iam.config;

import lombok.Data;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Data
public class FilterProperties {
    private boolean secure = true;
    private String loginPath = "/auth/login";
    private String loginCallbackPath = "/auth/login/callback";
    private String logoutPath = "/auth/logout";
    private String logoutCallbackPath = "/auth/logout/callback";
    private String sessionName = "session_token";
    private Duration sessionDuration = Duration.parse("P90D");
    private final List<String> urlPatterns = new ArrayList<>();
}
