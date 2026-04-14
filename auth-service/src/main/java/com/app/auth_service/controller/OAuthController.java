package com.app.auth_service.controller;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import com.app.auth_service.entity.UserEntity;
import com.app.auth_service.jwt.JwtUtil;
import com.app.auth_service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/auth")
public class OAuthController {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

 // OAuth Success API
    @GetMapping("/oauth-success")
    public void success(@AuthenticationPrincipal OAuth2User user, HttpServletResponse response) throws IOException {
        System.out.println("oauth-success hit");
        // Extract user details from Google
        String email = user.getAttribute("email");
        String name = user.getAttribute("name");

        // Check if user already exists in DB
        UserEntity existingUser = userRepository.findByUsername(email).orElse(null);

        if (existingUser == null) {
            // Create new user for OAuth login
            UserEntity newUser = new UserEntity();
            newUser.setUsername(email);
            // Always encode password (even dummy)
            newUser.setPassword(passwordEncoder.encode("oauth_user"));
            userRepository.save(newUser);
        }

        // Generate JWT token
        String token = jwtUtil.generateToken(email);

        // Encode the name just in case it contains spaces or special characters
        String encodedName = URLEncoder.encode(name != null ? name : email, StandardCharsets.UTF_8.toString());

        // IMPORTANT: Change this URL to match exactly where your frontend is running
        // For example, if you use VS Code Live Server, it might be http://127.0.0.1:5500
        String frontendUrl = "https://your-app.netlify.app/dashboard";

        // Build the redirect URL with the token and user info
//        String redirectUrl = frontendUrl + "?token=" + token + "&email=" + encodedName;

        String redirectUrl = frontendUrl + "?token=" + token + "&name=" + encodedName + "&email=" + email;
        
        // Redirect the user back to the frontend
        response.sendRedirect(redirectUrl);
    }
}