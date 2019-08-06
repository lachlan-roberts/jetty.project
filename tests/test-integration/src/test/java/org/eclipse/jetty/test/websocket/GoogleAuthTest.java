package org.eclipse.jetty.test.websocket;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.authentication.GoogleAuthenticator;
import org.eclipse.jetty.security.google.GoogleCredentials;
import org.eclipse.jetty.security.google.GoogleLoginService;
import org.eclipse.jetty.security.google.GoogleUserStore;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.security.Constraint;

public class GoogleAuthTest
{
    public static void main(String[] args) throws Exception
    {
        Server server = new Server(8080);
        ServletContextHandler context = new ServletContextHandler(server, "/", ServletContextHandler.SESSIONS | ServletContextHandler.SECURITY);

        context.addServlet(new ServletHolder(new DefaultServlet() {
            @Override
            protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
            {
                response.getWriter().append("authenticated: " + request.getUserPrincipal().getName());
            }
        }), "/*");

        context.addServlet(new ServletHolder(new DefaultServlet() {
            @Override
            protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
            {
                response.getWriter().append("error: you have made a severe and continuous lapse in judgement");
            }
        }), "/error");

        Constraint constraint = new Constraint();
        constraint.setName(Constraint.__GOOGLE_AUTH);
        constraint.setRoles(new String[]{"user","admin","moderator"});
        constraint.setAuthenticate(true);

        ConstraintMapping constraintMapping = new ConstraintMapping();
        constraintMapping.setConstraint(constraint);
        constraintMapping.setPathSpec("/*");

        ConstraintSecurityHandler securityHandler = new ConstraintSecurityHandler();
        securityHandler.addConstraintMapping(constraintMapping);

        String userId = "114260987481616800581";
        GoogleCredentials googleCredentials = new GoogleCredentials(null);
        googleCredentials.setUserId(userId);

        GoogleUserStore userStore = new GoogleUserStore();
        userStore.addUser(userId, googleCredentials, new String[]{"user"});
        GoogleLoginService loginService = new GoogleLoginService();
        loginService.setUserStore(userStore);
        securityHandler.setLoginService(loginService);

        final String clientId = "1051168419525-5nl60mkugb77p9j194mrh287p1e0ahfi.apps.googleusercontent.com";
        final String clientSecret = "XT_MIsSv_aUCGollauCaJY8S";
        final String redirectUri = "http://localhost:8080/authenticate";
        Authenticator authenticator = new GoogleAuthenticator(clientId, clientSecret, redirectUri, "/error", false);
        securityHandler.setAuthenticator(authenticator);

        context.setSecurityHandler(securityHandler);

        server.start();
        server.join();
    }
}
