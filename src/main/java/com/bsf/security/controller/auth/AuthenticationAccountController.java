package com.bsf.security.controller.auth;

import com.bsf.security.sec.auth.AuthenticationResponse;
import com.bsf.security.sec.auth.PasswordResetRequest;
import com.bsf.security.sec.model.token.TokenScopeCategoryEnum;
import com.bsf.security.service.auth.AuthenticationServiceImpl;
import com.bsf.security.util.UtilService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationAccountController {

    private final AuthenticationServiceImpl authenticationServiceImpl;

    @Autowired
    UtilService utilService;

    @PostMapping("/reset-password-send/{email}")
    public ResponseEntity<Void> sendResetPassword(@PathVariable("email") String email, HttpServletRequest httpRequest) {
        authenticationServiceImpl.sendResetPassword(email, utilService.getClientIP(httpRequest), utilService.getAppUrl(httpRequest));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset-password-verify/{token}")
    public ResponseEntity<Void> verifyResetToken(@PathVariable("token") String token) {
        // TODO: Togli il ritardo
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        authenticationServiceImpl.getAccountAndVerifyToken(token, TokenScopeCategoryEnum.BTD_RESET.getTokenScopeCategoryId());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset-password/{token}")
    public ResponseEntity<AuthenticationResponse> resetPassword(
            @RequestBody PasswordResetRequest request,
            @PathVariable("token") String token,
            HttpServletRequest httpRequest
    ) {
        // TODO: Togli il ritardo
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        return ResponseEntity.ok(authenticationServiceImpl.resetPassword(token, request, utilService.getClientIP(httpRequest)));
    }


}
