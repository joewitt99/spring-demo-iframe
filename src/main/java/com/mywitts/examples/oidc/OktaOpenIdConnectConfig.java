package com.mywitts.examples.oidc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2ClientConfiguration;
import org.springframework.security.web.RedirectStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Configuration
public class OktaOpenIdConnectConfig extends OAuth2ClientConfiguration{

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${okta.client-id}")
    private String clientId;

    @Value("${okta.client-secret}")
    private String clientSecret;

    @Value("${okta.token-uri}")
    private String accessTokenUri;

    @Value("${okta.authorization-uri}")
    private String userAuthorizationUri;

    @Value("${okta.redirect-uri}")
    private String redirectUri;

    @Bean
    public OAuth2ProtectedResourceDetails oktaOpenId() {
        final AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setUserAuthorizationUri(userAuthorizationUri);
        details.setScope(Arrays.asList("openid", "email", "profile"));
        details.setPreEstablishedRedirectUri(redirectUri);
        details.setUseCurrentUri(false);
        return details;
    }

    //@Override
    //public OAuth2ClientContextFilter oauth2ClientContextFilter() {
    //    logger.debug("Setting filter .... " );
    //    OAuth2ClientContextFilter filter = super.oauth2ClientContextFilter();
    //    filter.setRedirectStrategy(new RedirectStrategy() {
    //        @Override
    //        public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) {
    //            logger.debug("URL = " + url);
    //        }
    //    });
    //    return filter;
    //}

    @Bean
    public OAuth2RestTemplate oktaOpenIdTemplate(final OAuth2ClientContext clientContext) {
        final OAuth2RestTemplate template = new OAuth2RestTemplate(oktaOpenId(), clientContext);
        return template;
    }

}
