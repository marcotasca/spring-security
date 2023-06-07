package com.bsf.security.config;

import com.bsf.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;

    /**
     * Si occupa di cercare lo username nel database in base al nome utente.
     *
     * @return l'istanza di UserDetailsService configurata.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    /**
     * Si occupa di configurare l'oggetto AuthenticationProvider per la gestione dell'autenticazione.
     * Utilizza una implementazione di AuthenticationProvider tramite la classe DaoAuthenticationProvider.
     * Viene creata questa implementazione specificando i dettagli dell'utente e la funzione per
     * codificare la password.
     *
     * @return l'istanza di AuthenticationProvider configurata.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Si occupa di gestire l'autenticazione fornendo dei metodi necessari per aiutarci ad autenticare
     * un utente solo con username e password.
     *
     * @param config l'oggetto che detiene AuthenticationManager.
     * @return l'istanza di AuthenticationManager configurata.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Si occupa di fornire il metodo di codifica della password.
     *
     * @return l'istanza di PasswordEncoder configurata.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
