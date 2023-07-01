package com.example.springsecurity.model;

public record AuthResponse(
        String accessToken,
        String refreshToken
) {
}
