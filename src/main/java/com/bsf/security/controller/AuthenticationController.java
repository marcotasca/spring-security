package com.bsf.security.controller;

import com.bsf.security.event.auth.OnRegistrationEvent;
import com.bsf.security.sec.auth.AuthenticationRequest;
import com.bsf.security.sec.auth.AuthenticationResponse;
import com.bsf.security.service.auth.AuthenticationServiceImpl;
import com.bsf.security.sec.auth.RegisterRequest;
import com.bsf.security.util.UtilService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationServiceImpl authenticationServiceImpl;

    @Autowired
    UtilService utilService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(
            @RequestBody RegisterRequest request, HttpServletRequest httpRequest
    ) {
        authenticationServiceImpl.register(request, utilService.getClientIP(httpRequest), utilService.getAppUrl(httpRequest));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/register/verify/{token}")
    public ResponseEntity<Void> verifyTokenRegistration(
            @PathVariable("token") String token
    ) {
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        authenticationServiceImpl.verifyTokenRegistration(token);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request, HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(authenticationServiceImpl.authenticate(request, utilService.getClientIP(httpRequest)));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        authenticationServiceImpl.refreshToken(request, response);
    }

    @PostMapping("/password/reset")
    public ResponseEntity<Void> resetPassword(
            @RequestBody AuthenticationRequest request, HttpServletRequest httpRequest
    ) {
        return null;
    }

}
