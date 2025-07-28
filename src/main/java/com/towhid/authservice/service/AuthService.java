package com.towhid.authservice.service;

import com.towhid.authservice.dto.request.LoginRequest;
import com.towhid.authservice.dto.request.RegisterRequest;
import com.towhid.authservice.dto.request.VerificationRequest;
import com.towhid.authservice.dto.response.AuthResponse;
import com.towhid.authservice.entity.Token;
import com.towhid.authservice.entity.User;
import com.towhid.authservice.entity.TokenType;
import com.towhid.authservice.entity.Role;
import com.towhid.authservice.entity.Status;
import com.towhid.authservice.exception.AuthException;
import com.towhid.authservice.repository.TokenRepository;
import com.towhid.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final UserDetailsServiceImpl userDetailsService;

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new AuthException("Username is already taken");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AuthException("Email is already registered");
        }

        var user = User.builder()
                .name(request.getName())
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .status(Status.INACTIVE)
                .emailVerificationToken(UUID.randomUUID().toString())
                .build();

        userRepository.save(user);

        // Send verification email
        emailService.sendVerificationEmail(user.getEmail(), user.getName(), user.getEmailVerificationToken());

        return AuthResponse.builder()
                .message("Registration successful. Please check your email for verification.")
                .build();
    }

    public AuthResponse verifyEmail(VerificationRequest request) {
        var user = userRepository.findByEmailVerificationToken(request.getToken())
                .orElseThrow(() -> new AuthException("Invalid verification token"));

        user.setStatus(Status.ACTIVE);
        user.setEmailVerifiedAt(LocalDateTime.now());
        user.setEmailVerificationToken(null);
        userRepository.save(user);

        var jwtToken = jwtService.generateToken(userDetailsService.loadUserByUsername(user.getUsername()));
        var refreshToken = jwtService.generateRefreshToken(userDetailsService.loadUserByUsername(user.getUsername()));

        saveUserToken(user, jwtToken);

        return AuthResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .message("Email verified successfully")
                .build();
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsernameOrEmail(),
                        request.getPassword()
                )
        );

        var user = userRepository.findByUsernameOrEmail(request.getUsernameOrEmail())
                .orElseThrow(() -> new AuthException("User not found"));

        if (user.getStatus() != Status.ACTIVE) {
            throw new AuthException("Please verify your email first");
        }

        var jwtToken = jwtService.generateToken(userDetailsService.loadUserByUsername(user.getUsername()));
        var refreshToken = jwtService.generateRefreshToken(userDetailsService.loadUserByUsername(user.getUsername()));

        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);

        return AuthResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .message("Login successful")
                .build();
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public AuthResponse refreshToken(String refreshToken) {
        final String username = jwtService.extractUsername(refreshToken);
        if (username != null) {
            var user = this.userRepository.findByUsername(username)
                    .orElseThrow(() -> new AuthException("User not found"));

            if (jwtService.isTokenValid(refreshToken, userDetailsService.loadUserByUsername(username))) {
                var accessToken = jwtService.generateToken(userDetailsService.loadUserByUsername(username));
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);

                return AuthResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .message("Token refreshed successfully")
                        .build();
            }
        }
        throw new AuthException("Invalid refresh token");
    }
}