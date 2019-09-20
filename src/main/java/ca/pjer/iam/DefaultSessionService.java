package ca.pjer.iam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class DefaultSessionService implements SessionService {

    @Override
    public Map<String, Object> create(Map<String, Object> identity, String state, HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> session = new HashMap<>();
        session.put("jti", UUID.randomUUID().toString());
        session.put("sub", identity.get("sub"));
        return session;
    }

    @Override
    public Principal load(Map<String, Object> session, HttpServletRequest request, HttpServletResponse response) {
        return new ClaimsPrincipal(session);
    }

    @Override
    public void remove(Map<String, Object> session, HttpServletRequest request, HttpServletResponse response) {
    }
}
