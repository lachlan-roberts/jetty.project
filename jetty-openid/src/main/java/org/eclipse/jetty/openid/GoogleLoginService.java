//
//  ========================================================================
//  Copyright (c) 1995-2019 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.openid;

import java.io.IOException;
import java.security.Principal;
import javax.security.auth.Subject;
import javax.servlet.ServletRequest;

import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.PropertyUserStore;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.annotation.Name;
import org.eclipse.jetty.util.component.ContainerLifeCycle;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

public class GoogleLoginService extends ContainerLifeCycle implements LoginService
{
    private static final Logger LOG = Log.getLogger(GoogleLoginService.class);

    private static final String token_endpoint = "https://oauth2.googleapis.com/token";
    private static final String issuer = "https://accounts.google.com";

    private UserStore _userStore;
    private IdentityService identityService = new DefaultIdentityService();

    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;

    public GoogleLoginService(@Name("clientId") String clientId, @Name("clientSecret") String clientSecret, @Name("redirectUri") String redirectUri)
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

        // create user and return userIdentity
        GoogleUserPrincipal userPrincipal = new GoogleUserPrincipal(googleCredentials);
        Subject subject = new Subject();
        subject.getPrincipals().add(userPrincipal);
        subject.getPrivateCredentials().add(credentials);
        subject.setReadOnly();

        // TODO: do we need to use an IdentityService or is this fine??
        return new GoogleUserIdentity(subject, userPrincipal, _userStore);
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
    public void setUserStore(UserStore userStore)
    {
        updateBean(_userStore, userStore);
        _userStore = userStore;
    }

    /**
     * To facilitate testing.
     *
     * @return the UserStore
     */
    UserStore getUserStore()
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
