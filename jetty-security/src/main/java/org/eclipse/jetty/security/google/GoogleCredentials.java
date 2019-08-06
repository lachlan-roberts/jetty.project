package org.eclipse.jetty.security.google;

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

public class GoogleCredentials
{
    private static final Logger LOG = Log.getLogger(GoogleCredentials.class);

    private String clientId;
    private String userId;
    private String authCode;
    private Map<String, String> userInfo;

    public GoogleCredentials(String authCode)
    {
        this.authCode = authCode;
    }

    public Map<String, String> getUserInfo()
    {
        return userInfo;
    }

    public boolean redeemAuthCode(String clientId, String clientSecret, String redirectUri, String tokenEndpoint, String issuer)
    {
        if (LOG.isDebugEnabled())
            LOG.debug("redeemAuthCode() {}", this);

        this.clientId = clientId;

        if (authCode != null)
        {
            try
            {
                String jwt = getJWT(clientId, clientSecret, redirectUri, tokenEndpoint, issuer);
                userInfo = decodeJWT(jwt);
                userId = userInfo.get("sub");

            }
            catch (IOException e)
            {
                LOG.warn(e);
                return false;
            }
            finally
            {
                // reset authCode as it can only be used once
                authCode = null;
            }
        }

        return true;
    }

    public void update(GoogleCredentials credentials)
    {
        userInfo = credentials.userInfo;
    }

    public boolean validate()
    {
        if (LOG.isDebugEnabled())
            LOG.debug("validate() {}", this);

        // Check hasn't expired
        long expiry = Long.parseLong(userInfo.get("exp"));
        long currentTimeSeconds = (long)(System.currentTimeMillis()/1000F);
        if (currentTimeSeconds > expiry)
        {
            LOG.debug("validate() expired {}", System.currentTimeMillis(), expiry);
            return false;
        }

        // Check audience is our clientId
        String audience = userInfo.get("aud");
        String clientId = "1051168419525-5nl60mkugb77p9j194mrh287p1e0ahfi.apps.googleusercontent.com";
        if (!clientId.equals(audience))
        {
            LOG.debug("validate() wrong audience {}", false);
            return false;
        }

        LOG.debug("validate() is {}", true);
        return true;
    }

    public void setUserId(String userId)
    {
        this.userId = userId;
    }

    public String getUserId()
    {
        return userId;
    }

    private Map<String, String> decodeJWT(String jwt) throws IOException
    {
        LOG.warn("decodeJWT {}", jwt);

        // Decode the id_token JWT to get the user information
        // TODO: in production this verification should be done locally with appropriate libraries
        // NOTE: it is not necessary to check signature if this comes directly from google (authorisation code flow)
        final String tokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo";
        URL url = new URL(tokenInfoEndpoint+"?id_token="+jwt);
        InputStream content = (InputStream)url.getContent();
        Map<String, String> parse = (Map)JSON.parse(new String(content.readAllBytes()));
        return parse;
    }

    private String getJWT(String clientId, String clientSecret, String redirectUri, String tokenEndpoint, String issuer) throws IOException
    {
        LOG.warn("getJWT {}", authCode);

        // Use the auth code to get the id_token from the OpenID Provider
        String urlParameters = "code=" + authCode +
            "&client_id=" + clientId +
            "&client_secret=" + clientSecret +
            "&redirect_uri=" + redirectUri +
            "&grant_type=authorization_code";

        byte[] payload = urlParameters.getBytes(StandardCharsets.UTF_8);
        URL url = new URL(tokenEndpoint);
        HttpURLConnection connection = (HttpURLConnection)url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Host", issuer);
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
