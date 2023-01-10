package com.rl.oauthresourceserver.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserController {

    @GetMapping("/api/users")
    public String[] getUser(Principal principal) {
        return new String[]{"Shabbir", "Nikhil","Shivam"};
    }
}
