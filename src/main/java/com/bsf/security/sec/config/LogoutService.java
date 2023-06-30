package com.bsf.security.sec.config;

import com.bsf.security.sec.model.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // Recupero header di autorizzazione
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Variabile per il token
        final String jwt;

        // Se header recuperato è null o non inizia con la parola chiave "Bearer ", chiudo la richiesta
        if(authHeader == null || !authHeader.startsWith("Bearer ")) return;

        // Recupero il token alla settima posizione che è la lunghezza della parola chiave "Bearer "
        jwt = authHeader.substring(7);

        // Recupero il token salvato
        var storedToken = tokenRepository.findByAccessToken(jwt).orElse(null);

        // Se il token non è null lo disabilito e pulisco il contesto di spring
        if(storedToken != null) {
            // TODO: Elimina il token
//            storedToken.setExpired(true);
//            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
            SecurityContextHolder.clearContext();
        }
    }

}
