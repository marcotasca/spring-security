package com.bsf.security.sec.config;

import com.bsf.security.sec.model.account.PermissionEnum;
import com.bsf.security.sec.model.account.RoleEnum;
import com.bsf.security.sec.oauth.CustomOAuth2User;
import com.bsf.security.sec.oauth.CustomOAuth2UserService;
import com.bsf.security.sec.oauth.OAuth2AuthenticationSuccessHandler;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

    // JWT

    private final JwtAuthenticationFilter jwtAuthFilter;

    private final AuthenticationProvider authenticationProvider;

    private final LogoutHandler logoutHandler;

    private final JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    // OAuth

    private final CustomOAuth2UserService oauthUserService;

    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    //private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Bean
    public SecurityFilterChain jwtSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // Disabilito il Cross-Site Request Forgery
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // Abilita una whitelist di url
                        .requestMatchers("/api/v1/auth/**", "/login", "/oauth/**")
                        .permitAll()

                        // Imposto la sicurezza per i path
                        .requestMatchers("/api/v1/admin/**").hasAnyRole(RoleEnum.ADMIN.name())
                        .requestMatchers(HttpMethod.GET, "/api/v1/admin/**").hasAuthority(PermissionEnum.ADMIN_READ.name())
                        .requestMatchers(HttpMethod.POST, "/api/v1/admin/**").hasAuthority(PermissionEnum.ADMIN_CREATE.name())

                        // Per tutti gli altri url bisogna essere autenticati
                        .anyRequest()
                        .authenticated()
                )
                .formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                .oauth2Login(httpSecurityOAuth2LoginConfigurer -> httpSecurityOAuth2LoginConfigurer
                        .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                                .userService(oauthUserService)
                        )
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();

                                System.out.println(oauthUser.getEmail());
                                System.out.println(oauthUser.getName());
                                System.out.println(oauthUser.getAttributes());
                                System.out.println(oauthUser.getAuthorities());

                                //response.sendRedirect("/list");
                            }
                        })
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Forniamo AuthenticationProvider creato in ApplicationConfig
                .authenticationProvider(authenticationProvider)
                // Prima di tutto utilizziamo il filtro creato in JwtAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                // Aggiungo il path del logout con il suo handler
                .logout(logout -> logout
                        .logoutUrl("/api/v1/auth/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler(((request, response, authentication) -> SecurityContextHolder.clearContext()))
                )
                // Imposto come valore di status il 401 quando fallisce l'autenticazione
                .exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
                        httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(jwtAuthenticationEntryPoint)
                );


        return httpSecurity.build();
    }

}
