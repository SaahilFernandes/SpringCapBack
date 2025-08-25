package com.project.demo.controller;

import com.project.demo.model.RefreshToken;
import com.project.demo.model.User;
import com.project.demo.security.JwtUtil;
import com.project.demo.service.RefreshTokenService;
import com.project.demo.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;

    public AuthController(UserService userService, JwtUtil jwtUtil, AuthenticationManager authenticationManager, RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        try {
            String message = userService.register(user);
            return ResponseEntity.ok(Map.of("message", message));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * UPDATED: Authenticates a user and now returns both the access token and refresh token
     * in the JSON response body, in addition to setting the secure HttpOnly cookie.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> req, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.get("username"), req.get("password"))
            );

            String accessToken = jwtUtil.generateToken(authentication.getName());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(authentication.getName());

            // Set the HttpOnly cookie for security
            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken.getToken());
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(false); // For local HTTP. Set to true for production HTTPS.
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
            response.addCookie(refreshTokenCookie);

            // Return both tokens in the response body for the client's convenience
            return ResponseEntity.ok(Map.of(
                    "accessToken", accessToken,
                    "refreshToken", refreshToken.getToken()
            ));

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid username or password"));
        }
    }

    /**
     * UPDATED: Uses the refresh token from the HttpOnly cookie to issue a new access token
     * and a new refresh token (a practice known as token rotation for enhanced security).
     * Returns both new tokens in the response body.
     */
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        // Find the refresh token from the HttpOnly cookie
        Optional<String> refreshTokenOpt = Optional.ofNullable(request.getCookies())
                .flatMap(cookies -> Arrays.stream(cookies)
                        .filter(c -> "refreshToken".equals(c.getName()))
                        .map(Cookie::getValue)
                        .findFirst());

        if (refreshTokenOpt.isEmpty()) {
            return ResponseEntity.status(401).body(Map.of("error", "Refresh token not found in cookie"));
        }

        String oldToken = refreshTokenOpt.get();

        return refreshTokenService.findByToken(oldToken)
                .map(refreshTokenService::verifyExpiration)
                .map(rt -> {
                    // Token is valid, let's rotate it: invalidate the old one and create new ones.
                    String username = rt.getUsername();
                    refreshTokenService.deleteByToken(oldToken);

                    String newAccessToken = jwtUtil.generateToken(username);
                    RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(username);

                    // Set the new refresh token in the cookie
                    Cookie newRefreshTokenCookie = new Cookie("refreshToken", newRefreshToken.getToken());
                    newRefreshTokenCookie.setHttpOnly(true);
                    newRefreshTokenCookie.setSecure(false); // For local HTTP. Set to true for production HTTPS.
                    newRefreshTokenCookie.setPath("/");
                    newRefreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
                    response.addCookie(newRefreshTokenCookie);

                    // Return both new tokens in the response body
                    return ResponseEntity.ok(Map.of(
                            "accessToken", newAccessToken,
                            "refreshToken", newRefreshToken.getToken()
                    ));
                })
                .orElse(ResponseEntity.status(401).body(Map.of("error", "Invalid refresh token")));
    }

    /**
     * Logs the user out by deleting their refresh token from the server
     * and sending a command to the browser to clear the refresh token cookie.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        Optional<String> refreshTokenOpt = Optional.ofNullable(request.getCookies())
                .flatMap(cookies -> Arrays.stream(cookies)
                        .filter(c -> "refreshToken".equals(c.getName()))
                        .map(Cookie::getValue)
                        .findFirst());

        // Delete the token from the database/store on the server
        refreshTokenOpt.ifPresent(refreshTokenService::deleteByToken);

        // Instruct the browser to clear the cookie by setting its max age to 0
        Cookie clearedCookie = new Cookie("refreshToken", null);
        clearedCookie.setMaxAge(0);
        clearedCookie.setPath("/");
        response.addCookie(clearedCookie);

        return ResponseEntity.ok(Map.of("message", "Successfully logged out"));
    }
}