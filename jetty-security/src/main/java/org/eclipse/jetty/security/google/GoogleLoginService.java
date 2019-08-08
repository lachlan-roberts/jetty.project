package org.eclipse.jetty.security.google;

import java.io.IOException;
import java.security.Principal;
import javax.servlet.ServletRequest;

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

    private static final Logger LOG = Log.getLogger(GoogleLoginService.class);

    private static final String token_endpoint = "https://oauth2.googleapis.com/token";
    private static final String issuer = "https://accounts.google.com";

    private GoogleUserStore _userStore;
    private IdentityService identityService = new DefaultIdentityService();

    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;

    public GoogleLoginService(String clientId, String clientSecret, String redirectUri)
    {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
    }

    @Override
    public String getName()
    {
        return this.getClass().getSimpleName();
    }

    @Override
    public UserIdentity login(String identifier, Object credentials, ServletRequest req)
    {
        if (LOG.isDebugEnabled())
            LOG.debug("login({}, {}, {})", identifier, credentials, req);

        GoogleCredentials googleCredentials = (GoogleCredentials)credentials;
        try
        {
            googleCredentials.redeemAuthCode(clientId, clientSecret, redirectUri, token_endpoint, issuer);
        }
        catch (IOException e)
        {
            LOG.warn(e);
            return null;
        }

        UserIdentity userIdentity = _userStore.getUserIdentity(googleCredentials.getUserId());
        if (userIdentity != null)
        {
            // if we have a userIdentity update the credentials
            GoogleCredentials existingCredentials = ((GoogleUserPrincipal)userIdentity.getUserPrincipal()).getCredentials();
            existingCredentials.update(googleCredentials);
        }
        else
        {
            // otherwise we will register a new userIdentity
            _userStore.addUser(googleCredentials, new String[]{"user"});
            userIdentity = _userStore.getUserIdentity(googleCredentials.getUserId());
        }

        return userIdentity;
    }

    @Override
    public boolean validate(UserIdentity user)
    {
        Principal userPrincipal = user.getUserPrincipal();
        if (!(userPrincipal instanceof GoogleUserPrincipal))
            return false;

        GoogleCredentials credentials = ((GoogleUserPrincipal)userPrincipal).getCredentials();
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
