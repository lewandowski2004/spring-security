package com.rl.client.controller;

import com.rl.client.entity.User;
import com.rl.client.event.RegistrationCompleteEvent;
import com.rl.client.model.UserDto;
import com.rl.client.service.UserService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

@Controller
@Slf4j
@AllArgsConstructor
public class RegistrationController {

    private final UserService userService;
    private final ApplicationEventPublisher publisher;

    @GetMapping("/register/form")
    public String registerUserForm(Model model) {
        model.addAttribute("userDto", new UserDto());
        return "register";
    }

    @GetMapping("/login/oauth2")
    public String login(Model model) {
        return "login";
    }

    @PostMapping("/register/save")
    public String registerUserAction(@Valid @ModelAttribute("userDto") UserDto userDto,
                                     BindingResult result, Model model,
                                     final HttpServletRequest request) {

        if(userService.existingEmail(userDto.getEmail()))
            result.rejectValue("email", null, "Użytknownik o podanym adresie eamail już istnieje");
        if(result.hasErrors()){
            model.addAttribute("userDto", userDto);
            return "register";
        }
        if(!userDto.getPassword().equals(userDto.getConfirmPassword()))
            result.rejectValue("confirmPassword", null, "Powtórzone hasło nie może się różnić");

        User user = userService.registerUser(userDto);
        publisher.publishEvent(new RegistrationCompleteEvent(
                user,
                applicationUrl(request)
        ));
        return "redirect:/register/form?success";
    }

    private String applicationUrl(HttpServletRequest request) {
        return "http://" +
                request.getServerName() +
                ":" +
                request.getServerPort() +
                request.getContextPath();
    }
}
