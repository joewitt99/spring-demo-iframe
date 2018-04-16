package com.mywitts.examples.oidc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Configuration
@Controller
public class MainController {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${okta.login-uri}")
    private String loginUrl;

    @RequestMapping("/")
    @ResponseBody
    public final String home() {
        logger.debug("Starting OIDC Flow");
        final String username = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info(username);
        return "Welcome, " + username;
    }

}
