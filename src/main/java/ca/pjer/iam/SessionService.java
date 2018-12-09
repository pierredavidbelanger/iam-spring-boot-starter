package ca.pjer.iam;

import java.security.Principal;
import java.util.Map;

public interface SessionService {

    Map<String, Object> create(Map<String, Object> identity);

    Principal load(Map<String, Object> session);

    void remove(Map<String, Object> session);

}
