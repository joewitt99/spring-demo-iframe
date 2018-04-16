package com.mywitts.examples.oidc;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.header.writers.frameoptions.StaticAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

import java.net.URI;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

    @Value("${okta.issuer-uri}")
    private String issuerUri;

    @Value("${okta.audience}")
    private String audience;

    @Value("${okta.allow-origin}")
    private String allowOrigin;

    @Value("${okta.login-uri}")
    private String loginUrl;

    @Autowired
    private OAuth2RestTemplate restTemplate;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/resources/**");
    }

    @Bean
    public OpenIdConnectFilter myFilter() {
        OpenIdConnectFilter filter = new OpenIdConnectFilter("/okta-login", issuerUri, audience);
        filter.setRestTemplate(restTemplate);
        return filter;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilterAfter(new OAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAfter(myFilter(),
                        OAuth2ClientContextFilter.class)
                //.exceptionHandling().accessDeniedPage(loginUrl)
                //.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(loginUrl))
                .authorizeRequests()
                .anyRequest().authenticated().and().httpBasic().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/okta-login"));

        http.exceptionHandling().accessDeniedHandler((request, response, exc) -> {
            response.sendRedirect(loginUrl);
        });

        http.headers().frameOptions().and().addHeaderWriter(new XFrameOptionsHeaderWriter(new StaticAllowFromStrategy(new URI(allowOrigin)) ));
    }


}
