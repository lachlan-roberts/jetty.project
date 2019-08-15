package org.eclipse.jetty.openid;

import java.security.Principal;
import javax.security.auth.Subject;

import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.server.UserIdentity;

public class GoogleUserIdentity implements UserIdentity
{
    private final Subject subject;
    private final GoogleUserPrincipal userPrincipal;
    private final UserStore userStore;

    public GoogleUserIdentity(Subject subject, GoogleUserPrincipal userPrincipal, UserStore store)
    {
        this.subject = subject;
        this.userPrincipal = userPrincipal;
        this.userStore = store;
    }

    @Override
    public Subject getSubject()
    {
        return subject;
    }

    @Override
    public Principal getUserPrincipal()
    {
        return userPrincipal;
    }

    @Override
    public boolean isUserInRole(String role, Scope scope)
    {
        String userId = userPrincipal.getCredentials().getUserId();
        if (userStore != null)
            return userStore.getUserIdentity(userId).isUserInRole(role, scope);

        return false;
    }
}
