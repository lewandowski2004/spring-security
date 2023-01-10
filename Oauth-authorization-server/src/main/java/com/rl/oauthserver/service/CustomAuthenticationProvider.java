package com.rl.oauthserver.service;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        UserDetails user = customUserDetailsService.loadUserByUsername(username);
        return checkAccountDetails(user,password);
    }

    private Authentication checkAccountDetails(UserDetails user, String rawPassword) {
        if(!user.isAccountNonLocked())
            throw new LockedException("Twoje konto jest zablokowane");
        if(!user.isEnabled())
            throw new DisabledException("Twoje konto Nie zostało aktywowane");
        if(passwordEncoder.matches(rawPassword, user.getPassword()))
            return new UsernamePasswordAuthenticationToken(user.getUsername(),
                    user.getPassword(),
                    user.getAuthorities());
        else
            throw new BadCredentialsException("Błędny login lub hasło");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
