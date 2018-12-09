package ca.pjer.iam;

import java.util.Map;

public interface TokenService {

    String create(Map<String, Object> claims);

    Map<String, Object> parse(String token);

}
