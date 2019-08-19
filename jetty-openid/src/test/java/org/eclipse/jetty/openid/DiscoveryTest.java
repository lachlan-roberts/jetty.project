package org.eclipse.jetty.openid;

import java.io.InputStream;
import java.net.URI;
import java.util.Map;

import org.eclipse.jetty.util.ajax.JSON;
import org.junit.jupiter.api.Test;

public class DiscoveryTest
{

    @Test
    public void test() throws Exception
    {
        String path = "/.well-known/openid-configuration";
        String providerUri = "https://accounts.google.com/";
        URI provider = URI.create(providerUri).resolve(path);
        InputStream inputStream = provider.toURL().openConnection().getInputStream();
        String content = new String(inputStream.readAllBytes());
        Map discoveryDocument = (Map)JSON.parse(content);

        System.err.println("Issuer: " + discoveryDocument.get("issuer"));
        System.err.println("Auth Endpoint: " + discoveryDocument.get("authorization_endpoint"));
        System.err.println("Token Endpoint: " + discoveryDocument.get("token_endpoint"));
        System.err.println("UserInfo Endpoint: " + discoveryDocument.get("userinfo_endpoint"));
    }


}
