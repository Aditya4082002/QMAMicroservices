package com.app.auth_service.config;

import com.app.auth_service.entity.UserEntity;
import com.app.auth_service.jwt.JwtUtil;
import com.app.auth_service.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("email");
        String name  = oAuth2User.getAttribute("name");

        // Save user if not exists
        userRepository.findByUsername(email).orElseGet(() -> {
            UserEntity newUser = new UserEntity();
            newUser.setUsername(email);
            newUser.setPassword(passwordEncoder.encode("oauth_user"));
            return userRepository.save(newUser);
        });

        // Generate JWT
        String token = jwtUtil.generateToken(email);

        String encodedName = URLEncoder.encode(name != null ? name : email, StandardCharsets.UTF_8);

        // ⚠️ Change this to match your frontend URL
        String frontendUrl = "https://qmareact.netlify.app/dashboard";
//        String frontendUrl = "http://localhost:5500/dashboard.html";
        String redirectUrl  = frontendUrl + "?token=" + token + "&name=" + encodedName + "&email=" + email;

        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}