package ca.pjer.iam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Map;

public interface SessionService {

    Map<String, Object> create(Map<String, Object> identity, String state, HttpServletRequest request, HttpServletResponse response);

    Principal load(Map<String, Object> session, HttpServletRequest request, HttpServletResponse response);

    void remove(Map<String, Object> session, HttpServletRequest request, HttpServletResponse response);

}
