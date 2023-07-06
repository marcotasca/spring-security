package com.bsf.security.controller;

import com.bsf.security.sec.auth.AuthenticationRequest;
import com.bsf.security.sec.auth.AuthenticationResponse;
import com.bsf.security.service.auth.AuthenticationServiceImpl;
import com.bsf.security.sec.auth.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationServiceImpl authenticationServiceImpl;

    @PostMapping("/register")
    public ResponseEntity<Void> register(
            @RequestBody RegisterRequest request, HttpServletRequest httpRequest
    ) {
        String ipAddress = httpRequest.getRemoteAddr();
        authenticationServiceImpl.register(request, ipAddress);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/verify/{token}")
    public ResponseEntity<Void> verifyTokenRegistration(
            @PathVariable("token") String token
    ) {
        authenticationServiceImpl.verifyTokenRegistration(token);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody AuthenticationRequest request, HttpServletRequest httpRequest
    ) {
        String ipAddress = httpRequest.getRemoteAddr();
        return ResponseEntity.ok(authenticationServiceImpl.authenticate(request, ipAddress));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        authenticationServiceImpl.refreshToken(request, response);
    }

    // TODO: Crea un endpoint verify-email per verificare l'email inviata per email

}
