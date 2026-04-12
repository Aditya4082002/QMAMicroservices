package com.app.auth_service.controller;

import java.util.Map;

import com.app.auth_service.dto.RegisterRequestDTO;
import com.app.auth_service.entity.UserEntity;
import com.app.auth_service.jwt.JwtUtil;
import com.app.auth_service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
//@CrossOrigin(origins = "*")
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    //  LOGIN API
    @PostMapping("/login")
    public Map<String, String> login(@RequestBody Map<String, String> request) {

        String username = request.get("username");
        String password = request.get("password");

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        if (authentication.isAuthenticated()) {

            String token = jwtUtil.generateToken(username);

            return Map.of("token", token);
        }

        throw new RuntimeException("Invalid credentials");
    }

    //  REGISTER API
    @PostMapping("/register")
    public String register(@RequestBody RegisterRequestDTO request) {

        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return "User already exists";
        }

        UserEntity user = new UserEntity();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        userRepository.save(user);

        return "User registered successfully";
    }
}