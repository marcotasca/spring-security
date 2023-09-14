package com.bsf.security.service.auth;

import com.bsf.security.event.auth.OnRegistrationCompletedEvent;
import com.bsf.security.event.auth.OnRegistrationEvent;
import com.bsf.security.exception._common.BTExceptionName;
import com.bsf.security.exception.account.AccountNotFoundException;
import com.bsf.security.exception.account.DuplicateAccountException;
import com.bsf.security.exception.account.InvalidEmailAccountException;
import com.bsf.security.exception.account.PasswordsDoNotMatchException;
import com.bsf.security.exception.security.auth.AuthException;
import com.bsf.security.exception.security.auth.VerifyTokenRegistrationException;
import com.bsf.security.exception.security.jwt.InvalidJWTTokenException;
import com.bsf.security.sec.auth.AuthenticationRequest;
import com.bsf.security.sec.auth.AuthenticationResponse;
import com.bsf.security.sec.auth.RegisterRequest;
import com.bsf.security.sec.config.JwtService;
import com.bsf.security.sec.model.account.*;
import com.bsf.security.sec.model.provider.AuthProvider;
import com.bsf.security.sec.model.token.Token;
import com.bsf.security.sec.model.token.TokenScopeCategoryEnum;
import com.bsf.security.sec.model.token.TokenTypeEnum;
import com.bsf.security.service.account.AccountService;
import com.bsf.security.service.auth.provider.ProviderService;
import com.bsf.security.service.auth.token.TokenService;
import com.bsf.security.validation.email.EmailConstraintValidator;
import com.bsf.security.validation.password.PasswordConstraintValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final TokenService tokenService;

    private final ProviderService providerService;

    private final AccountService accountService;

    private final ApplicationEventPublisher eventPublisher;

    @Transactional
    @Override
    public void register(RegisterRequest request, String ipAddress, String appUrl) {
        // Controllo che l'account non esista già
        var duplicateAccount = accountService.findByEmail(request.getEmail());
        if (duplicateAccount.isPresent())
            throw new DuplicateAccountException(BTExceptionName.AUTH_REGISTRATION_DUPLICATE_USERNAME_ACCOUNT.name());

        // Controllo che l'email abbia un formato valido
        if (!EmailConstraintValidator.isValid(request.getEmail()))
            throw new InvalidEmailAccountException(BTExceptionName.INVALID_EMAIL.name());

        // Controllo che la password soddisfi i requisiti minimi
        PasswordConstraintValidator.isValid(request.getPassword());
        if (!request.getPassword().equals(request.getConfirmPassword()))
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
        var savedAccount = accountService.save(user);

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

        // Invio un evento quando viene completata la registrazione
        eventPublisher.publishEvent(new OnRegistrationEvent(this, savedAccount, accessToken, appUrl));

    }

    @Override
    public void verifyTokenRegistration(String registrationToken) {
        // Estraggo lo username dal token
        String username = jwtService.extractUsername(registrationToken);

        // Se lo username è nullo sollevo un'eccezione
        if (username == null) throw new VerifyTokenRegistrationException();

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
        if (token.isEmpty() || !token.get().getAccessToken().equals(registrationToken))
            throw new VerifyTokenRegistrationException();

        // Abilito l'account
        account.setStatus(new AccountStatus(AccountStatusEnum.Enabled.getStatusId()));
        accountService.save(account);

        // Elimino il token di registrazione
        tokenService.delete(token.get());

        // Invio un evento quando viene confermata la registrazione
        eventPublisher.publishEvent(new OnRegistrationCompletedEvent(this, account));

    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request, String ipAddress) {
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        // Controllo che l'email e la password non siano vuoti
        if (request.getEmail() == null) throw new AuthException(BTExceptionName.EMAIL_CAN_NOT_BE_EMPTY.name());
        if (request.getPassword() == null) throw new AuthException(BTExceptionName.PASSWORD_CAN_NOT_BE_EMPTY.name());

        // Se non corretto AuthenticationManager si occupa già di sollevare eccezioni
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // Se arrivato a questo punto significa che l'utente è corretto quindi recuperiamolo
        var user = accountService.findByEmail(request.getEmail())
                .orElseThrow();

        // Creo un token con i dati dell'utente creato
        var accessToken = jwtService.generateToken(user);

        // Creo il token di refresh
        var refreshToken = jwtService.generateRefreshToken(user);

        // Revoca tutti i token dello user
        tokenService.revokeAllAccountTokens(user);

        // Salva il token dell'utente
        Token token = tokenService.saveUserToken(
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
                .accessTokenExpirationDate(token.getAccessTokenExpiration())
                .refreshToken(refreshToken)
                .refreshTokenExpirationDate(token.getAccessTokenExpiration())
                .build();
    }

    @Override
    public AuthenticationResponse refreshToken(HttpServletRequest request, HttpServletResponse response) {
        // Recupero header di autorizzazione
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Variabile del token inviato
        final String refreshToken;

        // Variabile dello username
        final String userEmail;

        // Se header recuperato è null o non inizia con la parola chiave "Bearer ", chiudo la richiesta
        if (authHeader == null || !authHeader.startsWith("Bearer ")) throw new InvalidJWTTokenException();

        // Recupero il token alla settima posizione che è la lunghezza della parola chiave "Bearer "
        refreshToken = authHeader.substring(7);

        System.out.println("JWT Refresh -> {" + refreshToken + "}");

        // Estraggo lo username dal token
        userEmail = jwtService.extractUsername(refreshToken);

        // Se lo username non è nullo
        if (userEmail == null) throw new AccountNotFoundException(BTExceptionName.ACCOUNT_NOT_FOUND.name());

        // Recupero l'utente dal database
        var user = accountService.findByEmail(userEmail).orElseThrow();

        // Recupero il token
        Optional<Token> optionalToken = tokenService.findByRefreshToken(refreshToken);

        System.out.println(optionalToken);

        // Controllo che il token sia presente
        if(optionalToken.isEmpty()) {
            throw new InvalidJWTTokenException();
        }

        // Controllo che il token non sia scaduto
        var isValidToken = optionalToken
                .map(t -> !t.isRefreshTokenExpired())
                .orElse(false);

        // Controllo il token
        if (!jwtService.isValidToken(refreshToken, user) && isValidToken) throw new InvalidJWTTokenException();

        // Genero il token di accesso
        var accessToken = jwtService.generateToken(user);

        // Genero il token di refresh
        var currentRefreshToken = jwtService.generateRefreshToken(user);

        // Revoco tutti i token dell'utente
        tokenService.revokeAllAccountTokens(user);

        // Salvo il token dell'utente
        String ipAddress = request.getRemoteAddr();
        var token = tokenService.saveUserToken(
                user,
                accessToken,
                currentRefreshToken,
                ipAddress,
                TokenTypeEnum.BEARER,
                TokenScopeCategoryEnum.BTD_RW
        );

        // Creo la risposta da inviare
        return AuthenticationResponse
                .builder()
                .accessToken(token.getAccessToken())
                .accessTokenExpirationDate(token.getAccessTokenExpiration())
                .refreshToken(token.getRefreshToken())
                .refreshTokenExpirationDate(token.getAccessTokenExpiration())
                .build();

    }

}
