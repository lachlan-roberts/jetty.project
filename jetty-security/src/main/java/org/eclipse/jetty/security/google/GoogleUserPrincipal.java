package org.eclipse.jetty.security.google;

import java.io.Serializable;
import java.security.Principal;

public class GoogleUserPrincipal implements Principal, Serializable
{
    private static final long serialVersionUID = -6226920753748399662L;
    private final GoogleCredentials _credentials;

    public GoogleUserPrincipal(GoogleCredentials credentials)
    {
        _credentials = credentials;
    }

    public GoogleCredentials getCredentials()
    {
        return _credentials;
    }

    @Override
    public String getName()
    {
        return _credentials.getUserId();
    }

    @Override
    public String toString()
    {
        return _credentials.getUserId();
    }
}