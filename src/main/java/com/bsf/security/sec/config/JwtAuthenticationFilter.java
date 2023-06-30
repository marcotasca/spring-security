package com.bsf.security.sec.config;

import com.bsf.security.sec.model.token.Token;
import com.bsf.security.sec.model.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final UserDetailsService userDetailsService;

    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Recupero il token dal header della richiesta
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Variabile per il token JWT
        final String jwt;

        // Variabile per la email (username) all'interno del token
        final String userEmail;

        // Se header recuperato è null o non inizia con la parola chiave "Bearer ", chiudo la richiesta
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Recupero il token JWT alla settima posizione che è la lunghezza della parola chiave "Bearer "
        jwt = authHeader.substring(7);

        // Tramite una classe di supporto estraggo lo username dal token
        userEmail = jwtService.extractUsername(jwt);

        // Controllo che lo username non sia null e controllo nel contesto di sicurezza di spring che
        // l'utente non sia già autenticato
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Recupero l'utente dal database in base allo username
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // Controllo che il token non sia scaduto o revocato
            Optional<Token> accessToken = tokenRepository.findByAccessToken(jwt);
            System.out.println(accessToken.get().getAccessToken());
            var isValidToken = accessToken
                    .map(t -> !t.isExpired())
                    .orElse(false);

            // Controllo che il token inviato sia valido
            if(jwtService.isValidToken(jwt, userDetails) && isValidToken) {

                // Creo l'oggetto per il token dell'autenticazione di spring
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                // Aggiungo dettagli al token
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Faccio un update del SecurityContextHolder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }

        // Viene elaborata la richiesta una volta processata
        filterChain.doFilter(request, response);
    }

}
