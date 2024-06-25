package com.example.auth.domain.product.user;

public record RegisterDTO(String login, String password, UserRole role) {
}
