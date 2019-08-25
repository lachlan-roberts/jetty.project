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

package org.eclipse.jetty.security.openid;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.eclipse.jetty.util.ajax.JSON;

public class OpenIdConfiguration
{
    private static String CONFIG_PATH = "/.well-known/openid-configuration";

    private final String identityProvider;
    private final String authEndpoint;
    private final String tokenEndpoint;
    private final String userInfoEndpoint;
    private final String jwksUri;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;

    private List<String> scopes = new ArrayList<>();

    public OpenIdConfiguration(String provider, String clientId, String clientSecret, String redirectUri)
    {
        this.identityProvider = provider;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;

        Map discoveryDocument;
        try
        {
            if (provider.endsWith("/"))
                provider = provider.substring(0, provider.length()-1);

            URI providerUri = URI.create(provider + CONFIG_PATH);
            InputStream inputStream = providerUri.toURL().openConnection().getInputStream();
            String content = new String(inputStream.readAllBytes());
            discoveryDocument = (Map)JSON.parse(content);
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid identity provider", e);
        }

        String issuer = (String)discoveryDocument.get("issuer");
        // todo: if (!identityProvider.equals(issuer))

        authEndpoint = (String)discoveryDocument.get("authorization_endpoint");
        if (authEndpoint == null)
            throw new IllegalArgumentException();

        tokenEndpoint = (String)discoveryDocument.get("token_endpoint");
        if (tokenEndpoint == null)
            throw new IllegalArgumentException();

        userInfoEndpoint = (String)discoveryDocument.get("userinfo_endpoint");
        if (userInfoEndpoint == null)
            throw new IllegalArgumentException();

        jwksUri = (String)discoveryDocument.get("jwks_uri");
        if (jwksUri == null)
            throw new IllegalArgumentException();
    }

    public String getAuthEndpoint()
    {
        return authEndpoint;
    }

    public String getClientId()
    {
        return clientId;
    }

    public String getClientSecret()
    {
        return clientSecret;
    }

    public String getIdentityProvider()
    {
        return identityProvider;
    }

    public String getJwksUri()
    {
        return jwksUri;
    }

    public String getRedirectUri()
    {
        return redirectUri;
    }

    public String getTokenEndpoint()
    {
        return tokenEndpoint;
    }

    public String getUserInfoEndpoint()
    {
        return userInfoEndpoint;
    }

    public void addScopes(String... scopes)
    {
        for (String scope : scopes)
        {
            this.scopes.add(scope);
        }
    }

    public void addScope(String scope)
    {
        this.scopes.add(scope);
    }

    public List<String> getScopes()
    {
        return scopes;
    }
}
