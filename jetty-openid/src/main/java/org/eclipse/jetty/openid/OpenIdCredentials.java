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

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.eclipse.jetty.util.ajax.JSON;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

public class OpenIdCredentials
{
    private static final Logger LOG = Log.getLogger(OpenIdCredentials.class);

    private String clientId;
    private String authCode;
    private Map<String, String> userInfo;

    public OpenIdCredentials(String authCode)
    {
        this.authCode = authCode;
    }

    public String getUserId()
    {
        return userInfo.get("sub");
    }

    public Map<String, String> getUserInfo()
    {
        return userInfo;
    }

    public void redeemAuthCode(OpenIdConfiguration configuration) throws IOException
    {
        if (LOG.isDebugEnabled())
            LOG.debug("redeemAuthCode() {}", this);

        this.clientId = configuration.getClientId();
        if (authCode != null)
        {
            try
            {
                String jwt = getJWT(configuration);
                userInfo = decodeJWT(jwt);

                if (LOG.isDebugEnabled())
                    LOG.debug("userInfo {}", userInfo);
            }
            finally
            {
                // reset authCode as it can only be used once
                authCode = null;
            }
        }
    }

    public boolean validate()
    {
        if (authCode != null || clientId == null || userInfo == null)
            return false;

        // Check expiry
        long expiry = Long.parseLong(userInfo.get("exp"));
        long currentTimeSeconds = (long)(System.currentTimeMillis()/1000F);
        if (currentTimeSeconds > expiry)
        {
            if (LOG.isDebugEnabled())
                LOG.debug("validate() expired {}", this);
            return false;
        }

        // Check audience should be clientId
        String audience = userInfo.get("aud");
        if (!clientId.equals(audience))
        {
            if (LOG.isDebugEnabled())
                LOG.debug("validate() audience was not clientId {}", this);
            return false;
        }

        return true;
    }

    private Map<String, String> decodeJWT(String jwt) throws IOException
    {
        if (LOG.isDebugEnabled())
            LOG.debug("decodeJWT {}", jwt);

        // Decode the id_token JWT to get the user information
        // TODO: in production this verification should be done locally with appropriate libraries
        // NOTE: it is not necessary to check signature if this comes directly from google (authorisation code flow)
        final String tokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo";
        URL url = new URL(tokenInfoEndpoint+"?id_token="+jwt);
        InputStream content = (InputStream)url.getContent();
        Map<String, String> parse = (Map)JSON.parse(new String(content.readAllBytes()));
        return parse;
    }

    private String getJWT(OpenIdConfiguration config) throws IOException
    {
        if (LOG.isDebugEnabled())
            LOG.debug("getJWT {}", authCode);

        // Use the auth code to get the id_token from the OpenID Provider
        String urlParameters = "code=" + authCode +
            "&client_id=" + clientId +
            "&client_secret=" + config.getClientSecret() +
            "&redirect_uri=" + config.getRedirectUri() +
            "&grant_type=authorization_code";

        byte[] payload = urlParameters.getBytes(StandardCharsets.UTF_8);
        URL url = new URL(config.getTokenEndpoint());
        HttpURLConnection connection = (HttpURLConnection)url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Host", config.getIssuer());
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestProperty( "charset", "utf-8");

        try(DataOutputStream wr = new DataOutputStream(connection.getOutputStream()))
        {
            wr.write(payload);
        }

        // get response and extract id_token jwt
        InputStream content = (InputStream)connection.getContent();
        Map responseMap = (Map)JSON.parse(new String(content.readAllBytes()));
        return (String)responseMap.get("id_token");
    }
}
