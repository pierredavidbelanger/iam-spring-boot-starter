package ca.pjer.iam;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class DefaultSessionService implements SessionService {

    @Override
    public Map<String, Object> create(Map<String, Object> identity, String state) {
        Map<String, Object> session = new HashMap<>();
        session.put("jti", UUID.randomUUID().toString());
        session.put("sub", identity.get("sub"));
        return session;
    }

    @Override
    public Principal load(Map<String, Object> session) {
        return new ClaimsPrincipal(session);
    }

    @Override
    public void remove(Map<String, Object> session) {
    }
}
