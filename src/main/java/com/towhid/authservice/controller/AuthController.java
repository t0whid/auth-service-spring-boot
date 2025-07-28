package com.towhid.authservice.controller;

import com.towhid.authservice.dto.request.LoginRequest;
import com.towhid.authservice.dto.request.RegisterRequest;
import com.towhid.authservice.dto.request.VerificationRequest;
import com.towhid.authservice.dto.response.ApiResponse;
import com.towhid.authservice.dto.response.AuthResponse;
import com.towhid.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.ok(
                ApiResponse.builder()
                        .success(true)
                        .message(response.getMessage())
                        .build()
        );
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(
                ApiResponse.builder()
                        .success(true)
                        .message(response.getMessage())
                        .data(response)
                        .build()
        );
    }

    @GetMapping("/verify-email")
    public ResponseEntity<ApiResponse> verifyEmailGet(
            @RequestParam("token") String token) {
        VerificationRequest request = new VerificationRequest();
        request.setToken(token);
        return verifyEmail(request);
    }
    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse> verifyEmail(@Valid @RequestBody VerificationRequest request) {
        AuthResponse response = authService.verifyEmail(request);
        return ResponseEntity.ok(
                ApiResponse.builder()
                        .success(true)
                        .message(response.getMessage())
                        .data(response)
                        .build()
        );
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse> refreshToken(@RequestHeader("Authorization") String refreshToken) {
        if (refreshToken == null || !refreshToken.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(
                    ApiResponse.builder()
                            .success(false)
                            .message("Invalid refresh token")
                            .build()
            );
        }

        refreshToken = refreshToken.substring(7);
        AuthResponse response = authService.refreshToken(refreshToken);
        return ResponseEntity.ok(
                ApiResponse.builder()
                        .success(true)
                        .message(response.getMessage())
                        .data(response)
                        .build()
        );
    }
}