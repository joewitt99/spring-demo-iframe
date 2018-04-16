Spring Demo Application used with the Okta Widget Demo Iframe.

This is a simple Spring boot application which performs OIDC utilizing Okta as an Authorization server.  The output is "Welcome, [Okta Username]".

Perform the following to configure the application for the demo:  You can use the application.properties.example for reference.

1. Setup an OIDC application in Okta

    1. Copy the clientId and clientSecret to the application.properties file (okta.client-id, okta.client-secret)
    
    1. Specify the redirect URL.  If you make no port changes and run on localhost then this value would be http://localhost:8081/okta-login (okta.redirect-uri)
    
1. For this example, we will use the default Okta Authorization Server

    1. okta.authorization-uri = https://{your okta org}/oauth2/default/v1/authorize?prompt=none
        1. Please note that the URL must end with ?prompt=none
    
    1. okta.token-uri=https://{your okta org}/oauth2/default/v1/token
    
    1. okta.user-info-uri=https://{your okta org}/oauth2/default/v1/userinfo
    
    1. okta.jwk-set-uri=https://{your okta org}/oauth2/default/v1/keys
    
    1. okta.issuer-uri=https://{your okta org}/oauth2/default

    1. okta.audience=api://default
    
1. The final configurations are application specific use the following:
    
    1. okta.login-uri=http://localhost:4200/login
    1. okta.allow-origin=http://localhost:4200

Once all configurations are complete the application can be started using mvn spring-boot:run
