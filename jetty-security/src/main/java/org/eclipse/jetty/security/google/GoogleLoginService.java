package org.eclipse.jetty.security.google;

import java.io.Serializable;
import java.security.Principal;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.PropertyUserStore;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.component.ContainerLifeCycle;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

public class GoogleLoginService extends ContainerLifeCycle implements LoginService
{
    public static class GoogleUserPrincipal implements Principal, Serializable
    {
        private static final long serialVersionUID = -6226920753748399662L;
        private final String _name;
        private final GoogleCredentials _credentials;

        public GoogleUserPrincipal(String name, GoogleCredentials credentials)
        {
            _name = name;
            _credentials = credentials;
        }

        @Override
        public String getName()
        {
            return _name;
        }

        @Override
        public String toString()
        {
            return _name;
        }
    }


    private static final Logger LOG = Log.getLogger(GoogleLoginService.class);

    private static final String CSRF_TOKEN_ATTRIBUTE = "CSRF_TOKEN_ATTRIBUTE";

    private static final String token_endpoint = "https://oauth2.googleapis.com/token";
    private static final String issuer = "https://accounts.google.com";

    private GoogleUserStore _userStore;
    private IdentityService identityService = new DefaultIdentityService();

    private String clientId = "1051168419525-5nl60mkugb77p9j194mrh287p1e0ahfi.apps.googleusercontent.com";
    private String clientSecret = "XT_MIsSv_aUCGollauCaJY8S";
    private String redirectUri = "http://localhost:8080/authenticate";

    public GoogleLoginService(){} // TODO: remove

    public GoogleLoginService(String clientId, String clientSecret, String redirectUri)
    {
        // TODO: complete
    }

    @Override
    public String getName()
    {
        return this.getClass().getSimpleName();
    }

    @Override
    public UserIdentity login(String identifier, Object credentials, ServletRequest req)
    {
        HttpServletRequest request = (HttpServletRequest)req;

        // Verify anti-forgery state token
        String antiForgeryToken = (String)request.getSession().getAttribute(CSRF_TOKEN_ATTRIBUTE);
        if (antiForgeryToken == null || !antiForgeryToken.equals(request.getParameter("state")))
        {
            // TODO do something here???
            //response.sendError(HttpStatus.UNAUTHORIZED_401, "Invalid state parameter");
            return null;
        }

        LOG.warn("login requested {} {} {}", identifier, credentials, request);

        if (!(credentials instanceof GoogleCredentials))
            return null;

        GoogleCredentials googleCredentials = (GoogleCredentials)credentials;
        if (!googleCredentials.redeemAuthCode(clientId, clientSecret, redirectUri, token_endpoint, issuer))
            return null;

        UserIdentity userIdentity = _userStore.getUserIdentity(googleCredentials.getUserId());
        if (userIdentity != null)
        {
            GoogleCredentials existingCredentials = ((GoogleUserPrincipal)userIdentity.getUserPrincipal())._credentials;
            existingCredentials.update(googleCredentials);
        }

        LOG.warn("userInfo {}", googleCredentials.getUserInfo());
        LOG.warn("userIdentity {}", userIdentity);

        return userIdentity;
    }

    @Override
    public boolean validate(UserIdentity user)
    {
        Principal userPrincipal = user.getUserPrincipal();
        if (!(userPrincipal instanceof GoogleUserPrincipal))
            return false;

        GoogleCredentials credentials = ((GoogleUserPrincipal)userPrincipal)._credentials;
        return credentials.validate();
    }

    @Override
    public IdentityService getIdentityService()
    {
        return identityService;
    }

    /**
     * Configure the {@link UserStore} implementation to use.
     * If none, for backward compat if none the {@link PropertyUserStore} will be used
     *
     * @param userStore the {@link UserStore} implementation to use
     */
    public void setUserStore(GoogleUserStore userStore)
    {
        updateBean(_userStore, userStore);
        _userStore = userStore;
    }

    /**
     * To facilitate testing.
     *
     * @return the UserStore
     */
    GoogleUserStore getUserStore()
    {
        return _userStore;
    }

    @Override
    public void setIdentityService(IdentityService service)
    {
        if (isRunning())
            throw new IllegalStateException("Running");
        updateBean(identityService, service);
        identityService = service;
    }

    @Override
    public void logout(UserIdentity user)
    {
    }
}
