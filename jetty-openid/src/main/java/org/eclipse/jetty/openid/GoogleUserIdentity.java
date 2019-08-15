package org.eclipse.jetty.openid;

import java.security.Principal;
import javax.security.auth.Subject;

import org.eclipse.jetty.server.UserIdentity;

public class GoogleUserIdentity implements UserIdentity
{
    private final Subject subject;
    private final Principal userPrincipal;
    private final UserIdentity userIdentity;

    public GoogleUserIdentity(Subject subject, Principal userPrincipal)
    {
        this(subject, userPrincipal, null);
    }

    public GoogleUserIdentity(Subject subject, Principal userPrincipal, UserIdentity userIdentity)
    {
        this.subject = subject;
        this.userPrincipal = userPrincipal;
        this.userIdentity = userIdentity;
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
        return userIdentity == null ? false : userIdentity.isUserInRole(role, scope);
    }
}
