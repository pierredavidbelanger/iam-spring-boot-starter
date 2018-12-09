package ca.pjer.iam;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

@SuppressWarnings("unused")
public class ClaimsPrincipal implements Principal {

    private final String sub;
    private final Map<String, Object> session;

    ClaimsPrincipal(Map<String, Object> session) {
        sub = (String) session.get("sub");
        this.session = Collections.unmodifiableMap(session);
    }

    @Override
    public String getName() {
        return sub;
    }

    public Map<String, Object> getSession() {
        return session;
    }
}
