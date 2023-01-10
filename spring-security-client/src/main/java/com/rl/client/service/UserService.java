package com.rl.client.service;

import com.rl.client.entity.User;
import com.rl.client.entity.VerificationToken;
import com.rl.client.model.UserDto;

import java.util.Optional;

public interface UserService {
    User registerUser(UserDto userDto);

    void saveVerificationTokenForUser(String token, User user);

    String validateVerificationToken(String token);

    VerificationToken generateNewVerificationToken(String oldToken);

    User findUserByEmail(String email);

    void createPasswordResetTokenForUser(User user, String token);

    String validatePasswordResetToken(String token);

    Optional<User> getUserByPasswordResetToken(String token);

    void changePassword(User user, String newPassword);

    boolean checkIfValidOldPassword(User user, String oldPassword);

    boolean existingEmail(String email);
}
