package com.bsf.security.service.auth;

import com.bsf.security.sec.auth.AuthenticationRequest;
import com.bsf.security.sec.auth.AuthenticationResponse;
import com.bsf.security.sec.auth.PasswordResetRequest;
import com.bsf.security.sec.auth.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthenticationService {
    void register(RegisterRequest request, String ipAddress, String appUrl);
    void verifyRegistrationToken(String registrationToken);
    AuthenticationResponse authenticate(AuthenticationRequest request, String ipAddress);
    AuthenticationResponse refreshToken(HttpServletRequest request, HttpServletResponse response);
    void resetPassword(String email, String ipAddress, String appUrl);
    void verifyResetToken(String resetToken, PasswordResetRequest request);
}
