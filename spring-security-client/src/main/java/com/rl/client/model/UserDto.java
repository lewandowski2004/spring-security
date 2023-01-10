package com.rl.client.model;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

    @NotBlank(message = "Imię użytkownika jest wymagane")
    private String firstName;

    @NotBlank(message = "Nazwisko użytkownika jest wymagane")
    private String lastName;

    @NotBlank(message = "Email nie może być pusty")
    @Email(message = "podany email jest nieprawidłowy")
    private String email;

    @NotBlank(message = "Wprowadź hasło")
    private String password;

    @NotBlank(message = "Wprowadź hasło")
    private String confirmPassword;
}
