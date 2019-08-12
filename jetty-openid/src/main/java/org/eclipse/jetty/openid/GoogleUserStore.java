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

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.security.auth.Subject;

import org.eclipse.jetty.security.AbstractLoginService;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.component.AbstractLifeCycle;

public class GoogleUserStore extends AbstractLifeCycle
{
    private IdentityService _identityService = new DefaultIdentityService();
    private final Map<String, UserIdentity> _knownUserIdentities = new ConcurrentHashMap<>();

    public void addUser(String userId, String[] roles)
    {
        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("sub", userId);
        GoogleCredentials googleCredentials = new GoogleCredentials(userInfo);
        addUser(googleCredentials, roles);
    }

    public void addUser(GoogleCredentials credentials, String[] roles)
    {
        Principal userPrincipal = new GoogleUserPrincipal(credentials);
        Subject subject = new Subject();
        subject.getPrincipals().add(userPrincipal);
        subject.getPrivateCredentials().add(credentials);

        if (roles != null)
        {
            for (String role : roles)
            {
                subject.getPrincipals().add(new AbstractLoginService.RolePrincipal(role));
            }
        }

        subject.setReadOnly();
        _knownUserIdentities.put(credentials.getUserId(), _identityService.newUserIdentity(subject, userPrincipal, roles));
    }

    public void removeUser(String userId)
    {
        _knownUserIdentities.remove(userId);
    }

    public UserIdentity getUserIdentity(String userId)
    {
        return _knownUserIdentities.get(userId);
    }

    public IdentityService getIdentityService()
    {
        return _identityService;
    }

    public Map<String, UserIdentity> getKnownUserIdentities()
    {
        return _knownUserIdentities;
    }
}
