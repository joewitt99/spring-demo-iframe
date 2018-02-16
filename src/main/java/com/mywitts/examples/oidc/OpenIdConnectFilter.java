package com.mywitts.examples.oidc;

import com.okta.jwt.JoseException;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtHelper;
import com.okta.jwt.JwtVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OpenIdConnectFilter extends AbstractAuthenticationProcessingFilter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private JwtVerifier jwtVerifier;

    public OAuth2RestTemplate restTemplate;

    public OpenIdConnectFilter(String defaultFilterProcessingUrl, String issuerUri, String audience) {
        super(defaultFilterProcessingUrl);
        setAuthenticationManager(new NoopAuthenticationManager());
        logger.debug("issuerUri, Audience: " + issuerUri + ", " + audience );
        try {
            this.jwtVerifier = new JwtHelper()
                    .setIssuerUrl(issuerUri)
                    .setAudience(audience)
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        OAuth2AccessToken accessToken;
        try {
            accessToken = restTemplate.getAccessToken();
        } catch (final OAuth2Exception e) {
            throw new BadCredentialsException("Could not obtain access token", e);
        }
        try {
            final String idToken = accessToken.getAdditionalInformation().get("id_token").toString();
            System.out.println("Client Id " + restTemplate.getResource().getClientId());
            System.out.println("===== : " + idToken);
            //final Jwt tokenDecoded = this.jwtVerifier.decodeIdToken(idToken, restTemplate.getResource().getClientId());
            final Jwt tokenDecoded = this.jwtVerifier.decodeAccessToken(accessToken.getValue());
            System.out.println("===== : " + tokenDecoded.getClaims());

            final OpenIdConnectUserDetails user = new OpenIdConnectUserDetails(tokenDecoded.getClaims(), accessToken);
            return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        } catch (final JoseException e) {
            throw new BadCredentialsException("Could not obtain user details from token", e);
        }

    }

    public void setRestTemplate(OAuth2RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    private static class NoopAuthenticationManager implements AuthenticationManager {

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }

    }
}
