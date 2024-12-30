package org.example.authentication.controller;

import lombok.RequiredArgsConstructor;
import org.example.authentication.blacklist.TokenBlacklistService;
import org.example.authentication.model.User;
import org.example.authentication.repository.UserRepository;
import org.example.authentication.security.JwtUtil;
import org.example.authentication.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api")

public class AuthController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;

    @Autowired
    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtUtil jwtUtil,
                          TokenBlacklistService tokenBlacklistService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @PostMapping("/register")
    public String register(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "User registered successfully";
    }

    @PostMapping("/login")
    public String login(@RequestBody User loginUser) {
        // Fetch user from the database by username
        User storedUser = userRepository.findByUsername(loginUser.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));
        // Check if the password matches
        if (!passwordEncoder.matches(loginUser.getPassword(), storedUser.getPassword())) {
            throw new RuntimeException("Invalid password");
        }
        // Check if the role matches
        if (!loginUser.getRole().equals(storedUser.getRole())) {
            throw new RuntimeException("Role mismatch");
        }
        // Generate JWT token if everything is valid
        return jwtUtil.generateToken(storedUser.getUsername(), storedUser.getRole());
    }

    @PostMapping("/logout")
    public String logout(@RequestHeader("Authorization") String token) {
        tokenBlacklistService.blacklistToken(token.replace("Bearer ", ""));
        return "User logged out successfully";
    }
}
