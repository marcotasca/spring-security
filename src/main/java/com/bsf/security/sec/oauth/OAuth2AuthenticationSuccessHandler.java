package com.bsf.security.sec.oauth;

import com.bsf.security.sec.config.AppPropertiesConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AppPropertiesConfig appPropertiesConfig;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {
        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, "");
    }

//    private boolean isAuthorizedRedirectUri(String uri) {
//        URI clientRedirectUri = URI.create(uri);
//
//        return appPropertiesConfig.getAuthorizedRedirectUris()
//                .stream()
//                .anyMatch(authorizedRedirectUri -> {
//                    // Only validate host and port. Let the clients use different paths if they want to
//                    URI authorizedURI = URI.create(authorizedRedirectUri);
//                    return authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
//                            && authorizedURI.getPort() == clientRedirectUri.getPort();
//                });
//    }
}
