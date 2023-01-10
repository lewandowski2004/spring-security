package com.rl.client.config.SecurityUtils;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;
import java.util.stream.Collectors;

public class SecurityUtils {

    public final static String ROLE_CLAIM = "roles";
    public final static String ROLE_PREFIX = "ROLE_";

    public static List<GrantedAuthority> extractAuthorityFromClaims(Map<String, Object> claims) {
        return mapRolesToGrantedAuthorities(getRolesFromClaims(claims));
    }
    private static List<GrantedAuthority> mapRolesToGrantedAuthorities(Collection<String> roles) {
        return roles.stream()
                .filter(role -> role.startsWith(ROLE_PREFIX))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private static Collection<String> getRolesFromClaims(Map<String, Object> claims) {
        String s = claims.get(ROLE_CLAIM).toString().replace(" ", "");
        String[] rolesName = s.substring(1, s.length() - 1).split(",");
        return List.of(rolesName);
    }
}
