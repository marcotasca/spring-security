package com.bsf.security.sec.auth;

import com.bsf.security.sec.config.JwtService;
import com.bsf.security.sec.account.Account;
import com.bsf.security.sec.token.*;
import com.bsf.security.sec.account.AccountStatus;
import com.bsf.security.sec.account.AccountRepository;
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
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AccountRepository accountRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final TokenRepository tokenRepository;

    public AuthenticationResponse register(RegisterRequest request, HttpServletRequest httpRequest) {
        // Creo l'utente con ruolo di USER impostando tutti i campi necessari
        var user = Account
                .builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .createdAt(LocalDateTime.now())
                .status(new AccountStatus(1))
                .build();

        // Salvo l'utente appena creato
        var savedUser = accountRepository.save(user);

        // Creo un token con i dati dell'utente creato
        var accessToken = jwtService.generateToken(user);

        // Creo il token di refresh
        var refreshToken = jwtService.generateRefreshToken(user);

        // Salva il token dell'utente
        String ipAddress = httpRequest.getRemoteAddr();
        saveUserToken(savedUser, accessToken, refreshToken, ipAddress);

        // Ritorno il token appena generato
        return AuthenticationResponse
                .builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request, HttpServletRequest httpRequest) {
        // Se non corretto AuthenticationManager si occupa già di sollevare eccezioni
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // Se arrivato a questo punto significa che l'utente è corretto quindi recuperiamolo
        var user = accountRepository.findByEmail(request.getEmail())
                .orElseThrow();

        // Creo un token con i dati dell'utente creato
        // TODO: Rendilo disponibile per tutti, la firma di generateToken dovrà avere lo User e non UserDetails
        // TODO: iss prendilo come nome da application.yml, non portare first e last name, crea un path per l'utente
        HashMap<String, Object> extraClaims = new HashMap<>() {{
            put("iss", "Biotekna Plus");
            put("given_name", user.getFirstname());
            put("family_name", user.getLastname());
            put("roles", user.getAuthorities());
        }};
        var accessToken = jwtService.generateToken(extraClaims, user);

        // Creo il token di refresh
        var refreshToken = jwtService.generateRefreshToken(user);

        // Revoca tutti i token dello user
        revokeAllUserTokens(user);

        // Salva il token dell'utente
        String ipAddress = httpRequest.getRemoteAddr();
        saveUserToken(user, accessToken, refreshToken, ipAddress);

        // Ritorno il token appena generato
        return AuthenticationResponse
                .builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public void saveUserToken(Account account, String accessToken, String refreshToken, String ipAddress) {
        Date accessTokenExpiration = jwtService.extractExpiration(accessToken);
        Date refreshTokenExpiration = jwtService.extractExpiration(refreshToken);

        // Creo il token per l'utente
        var token = Token
                .builder()
                .account(account)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType(new TokenType(TokenTypeEnum.BEARER.getTokenTypeId()))
                .accessTokenExpiration(accessTokenExpiration)
                .refreshTokenExpiration(refreshTokenExpiration)
                .tokenScopeCategory(new TokenScopeCategory(TokenScopeCategoryEnum.BTD_REGISTRATION.getTokenScopeCategoryId()))
                .ipAddress(ipAddress)
                .build();

        // Salvo il token per l'utente
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(Account account) {
        // Recupero tutti i token validi dello user
        var validUserTokens = tokenRepository.findAllValidTokenByUser(account.getId());

        // Se non ce ne sono esco dalla funzione
        if(validUserTokens.isEmpty()) return;

        // Revoco ogni token dell'utente
        validUserTokens.forEach(token -> {
            // TODO: delete token
//            token.setExpired(true);
//            token.setRevoked(true);
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
            var user = this.accountRepository.findByEmail(userEmail).orElseThrow();

            if(jwtService.isValidToken(refreshToken, user)) {
                // Genero il token di accesso
                var accessToken = jwtService.generateToken(user);

                // Revoco tutti i token dell'utente
                revokeAllUserTokens(user);

                // Salvo il token dell'utente
                String ipAddress = request.getRemoteAddr();
                saveUserToken(user, accessToken, refreshToken, ipAddress);

                // Creo la risposta da inviare
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        // TODO: Crea un nuovo refresh token perché usa sempre lo stesso
                        .refreshToken(refreshToken)
                        .build();

                // Scrivo dentro lo stream di HttpServletResponse la risposta appena generata
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }

        }

    }

}
