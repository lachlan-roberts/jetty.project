package org.eclipse.jetty.openid;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Map;

import org.eclipse.jetty.util.ajax.JSON;

public class Configuration
{
    private static String CONFIG_PATH = "/.well-known/openid-configuration";

    private final String issuer;
    private final String authEndpoint;
    private final String tokenEndpoint;
    private final String userInfoEndpoint;
    private final String jwksUri;

    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;


    public Configuration(String provider, String clientId, String clientSecret, String redirectUri) throws IOException
    {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;

        URI providerUri = URI.create(provider).resolve(CONFIG_PATH);
        InputStream inputStream = providerUri.toURL().openConnection().getInputStream();
        String content = new String(inputStream.readAllBytes());
        Map discoveryDocument = (Map)JSON.parse(content);

        issuer = (String)discoveryDocument.get("issuer");
        authEndpoint = (String)discoveryDocument.get("authorization_endpoint");
        tokenEndpoint = (String)discoveryDocument.get("token_endpoint");
        userInfoEndpoint = (String)discoveryDocument.get("userinfo_endpoint");
        jwksUri = (String)discoveryDocument.get("jwks_uri");
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

    public String getIssuer()
    {
        return issuer;
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
}
