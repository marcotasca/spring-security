package com.bsf.security.service.auth;

import com.bsf.security.exception._common.BTExceptionName;
import com.bsf.security.exception.account.AccountNotFoundException;
import com.bsf.security.exception.account.DuplicateAccountException;
import com.bsf.security.exception.account.PasswordsDoNotMatchException;
import com.bsf.security.exception.security.auth.VerifyTokenRegistrationException;
import com.bsf.security.sec.auth.AuthenticationRequest;
import com.bsf.security.sec.auth.AuthenticationResponse;
import com.bsf.security.sec.auth.RegisterRequest;
import com.bsf.security.sec.config.JwtService;
import com.bsf.security.sec.model.account.*;
import com.bsf.security.sec.model.provider.AuthProvider;
import com.bsf.security.service.account.AccountService;
import com.bsf.security.service.auth.provider.ProviderService;
import com.bsf.security.sec.model.token.*;
import com.bsf.security.service.auth.token.TokenService;
import com.bsf.security.validation.password.PasswordConstraintValidator;
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
import java.util.HashMap;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AccountRepository accountRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final TokenRepository tokenRepository;

    private final TokenService tokenService;

    private final ProviderService providerService;

    private final AccountService accountService;

    @Override
    public void register(RegisterRequest request, String ipAddress) {
        // Controllo che l'account non esista già
        var duplicateAccount = accountRepository.findByEmail(request.getEmail());
        if(duplicateAccount.isPresent())
            throw new DuplicateAccountException(BTExceptionName.AUTH_REGISTRATION_DUPLICATE_USERNAME_ACCOUNT.name());

        // Controllo che la password soddisfi i requisiti minimi
        PasswordConstraintValidator.isValid(request.getPassword());
        if(!request.getPassword().equals(request.getConfirmPassword()))
            throw new PasswordsDoNotMatchException(BTExceptionName.AUTH_REGISTRATION_PASSWORDS_DO_NOT_MATCH.name());

        // Creo l'utente con ruolo di USER impostando tutti i campi necessari
        var user = Account
                .builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(new Role(RoleEnum.ADMIN.getRoleId()))
                .createdAt(LocalDateTime.now())
                .status(new AccountStatus(AccountStatusEnum.Pending.getStatusId()))
                .build();

        // Salvo l'utente appena creato
        var savedAccount = accountRepository.save(user);

        // Salvo il provider collegato all'account
        providerService.addProviderToAccount(AuthProvider.LOCAL.getProviderId(), savedAccount.getId());

        // Creo un token per la verifica della registrazione
        var accessToken = jwtService.generateRegistrationToken(user);

        // Salva il token dell'utente
        tokenService.saveUserToken(
                savedAccount,
                accessToken,
                null,
                ipAddress,
                TokenTypeEnum.BEARER,
                TokenScopeCategoryEnum.BTD_REGISTRATION
        );

        // TODO: Invia l'email

    }

    @Override
    public void verifyTokenRegistration(String registrationToken) {
        // Estraggo lo username dal token
        String username = jwtService.extractUsername(registrationToken);

        // Se lo username è nullo sollevo un'eccezione
        if(username == null) throw new VerifyTokenRegistrationException();

        // Recupero l'utente dal database
        var account = accountService
                .findByEmail(username)
                .orElseThrow(() -> new AccountNotFoundException(BTExceptionName.ACCOUNT_NOT_FOUND.name()));

        // Controllo che il token sia valido altrimenti sollevo un'eccezione
        if (!jwtService.isValidToken(registrationToken, account)) throw new VerifyTokenRegistrationException();

        // Recupero il token in base all'account ID e allo scopo di registrazione
        Optional<Token> token = tokenService.findByAccountIdAndTokenScopeCategoryId(
                account.getId(), TokenScopeCategoryEnum.BTD_REGISTRATION.getTokenScopeCategoryId()
        );

        // Se il token è presente e uguale a quello che mi è arrivato
        if(token.isEmpty() || !token.get().getAccessToken().equals(registrationToken))
            throw new VerifyTokenRegistrationException();

        account.setStatus(new AccountStatus(AccountStatusEnum.Enabled.getStatusId()));
        accountService.save(account);

        tokenService.delete(token.get());
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request, String ipAddress) {
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
//        HashMap<String, Object> extraClaims = new HashMap<>() {{
//            put("iss", "Biotekna Plus");
//            put("given_name", user.getFirstname());
//            put("family_name", user.getLastname());
//            put("roles", user.getAuthorities());
//        }};
        var accessToken = jwtService.generateToken(new HashMap<>(), user);

        // Creo il token di refresh
        var refreshToken = jwtService.generateRefreshToken(user);

        // Revoca tutti i token dello user
        revokeAllUserTokens(user);

        // Salva il token dell'utente
        tokenService.saveUserToken(
                user,
                accessToken,
                refreshToken,
                ipAddress,
                TokenTypeEnum.BEARER,
                TokenScopeCategoryEnum.BTD_RW
        );

        // Ritorno il token appena generato
        return AuthenticationResponse
                .builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
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

        // Estraggo lo username dal token
        userEmail = jwtService.extractUsername(refreshToken);

        // Se lo username non è nullo
        if(userEmail != null) {

            // Recupero l'utente dal database
            var user = this.accountRepository.findByEmail(userEmail).orElseThrow();

            if(jwtService.isValidToken(refreshToken, user)) {
                // Genero il token di accesso
                var accessToken = jwtService.generateToken(user);

                // Genero il token di refresh
                var currentRefreshToken = jwtService.generateRefreshToken(user);

                // Revoco tutti i token dell'utente
                revokeAllUserTokens(user);

                // Salvo il token dell'utente
                String ipAddress = request.getRemoteAddr();
                tokenService.saveUserToken(
                        user,
                        accessToken,
                        currentRefreshToken,
                        ipAddress,
                        TokenTypeEnum.BEARER,
                        TokenScopeCategoryEnum.BTD_RW
                );

                // Creo la risposta da inviare
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(currentRefreshToken)
                        .build();

                // Scrivo dentro lo stream di HttpServletResponse la risposta appena generata
                try {
                    new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

        }

    }

    @Override
    public void revokeAllUserTokens(Account account) {
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

}