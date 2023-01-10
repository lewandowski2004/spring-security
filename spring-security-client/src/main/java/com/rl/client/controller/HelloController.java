package com.rl.client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.Principal;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;


@RestController
public class HelloController {


    @Autowired
    private WebClient webClient;

    @GetMapping("/index")
    public String index() {
        return "Index page";
    }

    @GetMapping("/api/hello")
    public String hello(@AuthenticationPrincipal OAuth2User oAuth2User) {
        return "Hello " +oAuth2User.getName();
    }

    @GetMapping("/api/users")
    public String[] users(
            @RegisteredOAuth2AuthorizedClient("api-client-authorization-code")
                    OAuth2AuthorizedClient client){
        return this.webClient
                .get()
                .uri("http://127.0.0.1:8090/api/users")
                .attributes(oauth2AuthorizedClient(client))
                .retrieve()
                .bodyToMono(String[].class)
                .block();
    }

    @GetMapping("/admin/hello")
    public String helloAdmin(Principal principal) {
        return "Hello ADMIN";
    }

    @GetMapping("/test/hello")
    public String helloTest(Principal principal) {
        return "Hello TEST";
    }

    @GetMapping("/user/hello")
    public String helloUser(Principal principal) {
        return "Hello USER";
    }


}
