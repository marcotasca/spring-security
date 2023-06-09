package com.bsf.security.auth;

import com.bsf.security.config.JwtService;
import com.bsf.security.token.Token;
import com.bsf.security.token.TokenRepository;
import com.bsf.security.token.TokenType;
import com.bsf.security.user.Role;
import com.bsf.security.user.User;
import com.bsf.security.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final TokenRepository tokenRepository;

    public AuthenticationResponse register(RegisterRequest request) {
        // Creo l'utente con ruolo di USER impostando tutti i campi necessari
        var user = User
                .builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        // Salvo l'utente appena creato
        var savedUser = userRepository.save(user);

        // Creo un token con i dati dell'utente creato
        var jwtToken = jwtService.generateToken(user);

        // Creo il token di refresh
        var refreshToken = jwtService.generateRefreshToken(user);

        // Salva il token dell'utente
        saveUserToken(savedUser, jwtToken);

        // Ritorno il token appena generato
        return AuthenticationResponse
                .builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // Se non corretto AuthenticationManager si occupa già di sollevare eccezioni
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // Se arrivato a questo punto significa che l'utente è corretto quindi recuperiamolo
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();

        // Creo un token con i dati dell'utente creato
        HashMap<String, Object> extraClaims = new HashMap<>() {{
            put("iss", "Biotekna Plus");
            put("given_name", user.getFirstname());
            put("family_name", user.getLastname());
            put("roles", user.getRole());
        }};
        var jwtToken = jwtService.generateToken(extraClaims, user);

        // Creo il token di refresh
        var refreshToken = jwtService.generateRefreshToken(user);

        // Revoca tutti i token dello user
        revokeAllUserTokens(user);

        // Salva il token dell'utente
        saveUserToken(user, jwtToken);

        // Ritorno il token appena generato
        return AuthenticationResponse
                .builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public void saveUserToken(User user, String jwtToken) {
        // Creo il token per l'utente
        var token = Token
                .builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        // Salvo il token per l'utente
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        // Recupero tutti i token validi dello user
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());

        // Se non ce ne sono esco dalla funzione
        if(validUserTokens.isEmpty()) return;

        // Revoco ogni token dell'utente
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });

        // Salvo  i token
        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Recupero header di autorizzazione
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Variabile del token inviato
        final String refreshToken;

        // Variabile dello username
        final String userEmail;

        // Se header recuperato è null o non inizia con la parola chiave "Bearer ", chiudo la richiesta
        if(authHeader == null || !authHeader.startsWith("Bearer ")) return;

        // Recupero il token alla settima posizione che è la lunghezza della parola chiave "Bearer "
        refreshToken = authHeader.substring(7);

        // Tramite una classe di supporto estraggo lo username dal token
        userEmail = jwtService.extractUsername(refreshToken);

        // Se lo username non è nullo
        if(userEmail != null) {

            // Recupero l'utente dal database
            var user = this.userRepository.findByEmail(userEmail).orElseThrow();

            if(jwtService.isValidToken(refreshToken, user)) {
                // Genero il token di accesso
                var accessToken = jwtService.generateToken(user);

                // Revoco tutti i token dell'utente
                revokeAllUserTokens(user);

                // Salvo il token dell'utente
                saveUserToken(user, accessToken);

                // Creo la risposta da inviare
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();

                // Scrivo dentro lo stream di HttpServletResponse la risposta appena generata
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }

        }

    }

}
