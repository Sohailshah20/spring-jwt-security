package com.example.springsecurity.controller;

import com.example.springsecurity.model.AuthResponse;
import com.example.springsecurity.model.AuthRequest;
import com.example.springsecurity.model.RegisterRequest;
import com.example.springsecurity.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @RequestBody RegisterRequest registerRequest
    ) {
        return ResponseEntity.ok(authenticationService.register(registerRequest));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthResponse> authenticate(
            @RequestBody AuthRequest authRequest
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(authRequest));
    }
}
