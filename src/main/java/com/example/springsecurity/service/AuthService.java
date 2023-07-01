package com.example.springsecurity.service;

import com.example.springsecurity.model.AuthRequest;
import com.example.springsecurity.model.AuthResponse;
import com.example.springsecurity.model.RegisterRequest;
import com.example.springsecurity.repository.UserRepository;
import com.example.springsecurity.user.Role;
import com.example.springsecurity.user.SecurityUser;
import com.example.springsecurity.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager manager;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JWTService jwtService, AuthenticationManager manager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.manager = manager;
    }

    public ResponseEntity<AuthResponse> register(RegisterRequest registerRequest) {
        userRepository.findByEmail(registerRequest.getEmail())
                .ifPresent(r -> {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Email already Exists");
                });
        User user = new User();
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setRole(Role.USER);
        SecurityUser securityUser = new SecurityUser(user);
        userRepository.save(user);
        return ResponseEntity.ok(getAuthResponse(securityUser));
    }

    public AuthResponse authenticate(AuthRequest request){
        manager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        return getAuthResponse(new SecurityUser(user));

    }

    private AuthResponse getAuthResponse(SecurityUser user) {
        Map<String, String> tokenMap = jwtService.generateTokens(user);
        return new AuthResponse(
                tokenMap.get("accessToken"),
                tokenMap.get("refreshToken")
        );
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUserEmail(refreshToken);
        if (userEmail != null){
            var user = userRepository.findByEmail(userEmail)
                    .orElseThrow();
            var securityUser = new SecurityUser(user);
            if (jwtService.isTokenValid(refreshToken,securityUser)){
                var accessToken = jwtService.generateAccessToken(new HashMap<>(), securityUser);
                var authResponse = new AuthResponse(
                        accessToken,
                        refreshToken
                );
                new ObjectMapper().writeValue(response.getOutputStream(),authResponse);
            }
        }
    }
}
