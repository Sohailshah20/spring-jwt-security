package com.example.springsecurity.service;

import com.example.springsecurity.config.JWTService;
import com.example.springsecurity.model.AuthRequest;
import com.example.springsecurity.model.AuthResponse;
import com.example.springsecurity.model.RegisterRequest;
import com.example.springsecurity.repository.UserRepository;
import com.example.springsecurity.user.Role;
import com.example.springsecurity.user.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager manager;

    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder, JWTService jwtService, AuthenticationManager manager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.manager = manager;
    }

    public AuthResponse register(RegisterRequest registerRequest){
        User user = new User();
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setRole(Role.USER);
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        AuthResponse response = new AuthResponse();
        response.setToken(jwtToken);
        return response;
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
        var jwtToken = jwtService.generateToken(user);
        AuthResponse response = new AuthResponse();
        response.setToken(jwtToken);
        return response;

    }
}
