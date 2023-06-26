package com.bsf.security.sec.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request, HttpServletRequest httpRequest
    ) {
        String ipAddress = httpRequest.getRemoteAddr();
        return ResponseEntity.ok(authenticationService.register(request, ipAddress));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody AuthenticationRequest request, HttpServletRequest httpRequest
    ) {
        String ipAddress = httpRequest.getRemoteAddr();
        return ResponseEntity.ok(authenticationService.authenticate(request, ipAddress));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        authenticationService.refreshToken(request, response);
    }

    // TODO: Crea un endpoint verify-email per verificare l'email inviata per email

}
