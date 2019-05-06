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

package org.eclipse.jetty.websocket.core.client;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.HttpConversation;
import org.eclipse.jetty.client.HttpRequest;
import org.eclipse.jetty.client.HttpResponse;
import org.eclipse.jetty.client.HttpResponseException;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.api.Response;
import org.eclipse.jetty.client.api.Result;
import org.eclipse.jetty.client.http.HttpConnectionOverHTTP;
import org.eclipse.jetty.client.http.HttpConnectionUpgrader;
import org.eclipse.jetty.http.HttpField;
import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpScheme;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.io.ByteBufferPool;
import org.eclipse.jetty.io.Connection;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.util.B64Code;
import org.eclipse.jetty.util.QuotedStringTokenizer;
import org.eclipse.jetty.util.StringUtil;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.eclipse.jetty.websocket.core.Behavior;
import org.eclipse.jetty.websocket.core.ExtensionConfig;
import org.eclipse.jetty.websocket.core.FrameHandler;
import org.eclipse.jetty.websocket.core.UpgradeException;
import org.eclipse.jetty.websocket.core.WebSocketConstants;
import org.eclipse.jetty.websocket.core.WebSocketException;
import org.eclipse.jetty.websocket.core.internal.ExtensionStack;
import org.eclipse.jetty.websocket.core.internal.Negotiated;
import org.eclipse.jetty.websocket.core.internal.WebSocketChannel;
import org.eclipse.jetty.websocket.core.internal.WebSocketConnection;
import org.eclipse.jetty.websocket.core.internal.WebSocketCore;

public abstract class ClientUpgradeRequest extends HttpRequest implements Response.CompleteListener, HttpConnectionUpgrader
{
    public static ClientUpgradeRequest from(WebSocketCoreClient webSocketClient, URI requestURI, FrameHandler frameHandler)
    {
        return new ClientUpgradeRequest(webSocketClient, requestURI)
        {
            @Override
            public FrameHandler getFrameHandler(WebSocketCoreClient coreClient, HttpResponse response)
            {
                return frameHandler;
            }
        };
    }

    private static final Logger LOG = Log.getLogger(ClientUpgradeRequest.class);
    protected final CompletableFuture<FrameHandler.CoreSession> futureCoreSession;
    private final WebSocketCoreClient wsClient;
    private List<UpgradeListener> upgradeListeners = new ArrayList<>();

    public ClientUpgradeRequest(WebSocketCoreClient webSocketClient, URI requestURI)
    {
        super(webSocketClient.getHttpClient(), new HttpConversation(), requestURI);

        // Validate websocket URI
        if (!requestURI.isAbsolute())
        {
            throw new IllegalArgumentException("WebSocket URI must be absolute");
        }

        if (StringUtil.isBlank(requestURI.getScheme()))
        {
            throw new IllegalArgumentException("WebSocket URI must include a scheme");
        }

        String scheme = requestURI.getScheme().toLowerCase(Locale.ENGLISH);
        if (("ws".equals(scheme) == false) && ("wss".equals(scheme) == false))
        {
            throw new IllegalArgumentException("WebSocket URI scheme only supports [ws] and [wss], not [" + scheme + "]");
        }

        if (requestURI.getHost() == null)
        {
            throw new IllegalArgumentException("Invalid WebSocket URI: host not present");
        }

        this.wsClient = webSocketClient;
        this.futureCoreSession = new CompletableFuture<>();

        // TODO: this is invalid for HTTP/2 requests
        method(HttpMethod.GET);
        version(HttpVersion.HTTP_1_1);

        getConversation().setAttribute(HttpConnectionUpgrader.class.getName(), this);
    }

    public void addListener(UpgradeListener listener)
    {
        upgradeListeners.add(listener);
    }

    public void addExtensions(ExtensionConfig... configs)
    {
        HttpFields headers = getHeaders();
        for (ExtensionConfig config : configs)
            headers.add(HttpHeader.SEC_WEBSOCKET_EXTENSIONS, config.getParameterizedName());
    }

    public void addExtensions(String... configs)
    {
        HttpFields headers = getHeaders();
        for (String config : configs)
            headers.add(HttpHeader.SEC_WEBSOCKET_EXTENSIONS, ExtensionConfig.parse(config).getParameterizedName());
    }

    public List<ExtensionConfig> getExtensions()
    {
        List<ExtensionConfig> extensions = getHeaders().getCSV(HttpHeader.SEC_WEBSOCKET_EXTENSIONS, true)
                .stream()
                .map(ExtensionConfig::parse)
                .collect(Collectors.toList());

        return extensions;
    }

    public void setExtensions(List<ExtensionConfig> configs)
    {
        HttpFields headers = getHeaders();
        headers.remove(HttpHeader.SEC_WEBSOCKET_EXTENSIONS);
        for (ExtensionConfig config : configs)
            headers.add(HttpHeader.SEC_WEBSOCKET_EXTENSIONS, config.getParameterizedName());
    }

    public List<String> getSubProtocols()
    {
        List<String> subProtocols = getHeaders().getCSV(HttpHeader.SEC_WEBSOCKET_SUBPROTOCOL, true);
        return subProtocols;
    }

    public void setSubProtocols(String... protocols)
    {
        HttpFields headers = getHeaders();
        headers.remove(HttpHeader.SEC_WEBSOCKET_SUBPROTOCOL);
        for (String protocol : protocols)
            headers.add(HttpHeader.SEC_WEBSOCKET_SUBPROTOCOL, protocol);
    }

    public void setSubProtocols(List<String> protocols)
    {
        HttpFields headers = getHeaders();
        headers.remove(HttpHeader.SEC_WEBSOCKET_SUBPROTOCOL);
        for (String protocol : protocols)
            headers.add(HttpHeader.SEC_WEBSOCKET_SUBPROTOCOL, protocol);
    }

    @Override
    public void send(final Response.CompleteListener listener)
    {
        // TODO: this adds only the HTTP/1.1 headers, (if HTTP/2 send CONNECT request)
        initWebSocketHeaders();
        super.send(listener);
    }

    public CompletableFuture<FrameHandler.CoreSession> sendAsync()
    {
        send(this);
        return futureCoreSession;
    }

    @SuppressWarnings("Duplicates")
    @Override
    public void onComplete(Result result)
    {
        if (LOG.isDebugEnabled())
        {
            LOG.debug("onComplete() - {}", result);
        }

        URI requestURI = result.getRequest().getURI();
        Response response = result.getResponse();
        int responseStatusCode = response.getStatus();
        String responseLine = responseStatusCode + " " + response.getReason();

        if (result.isFailed())
        {
            if (LOG.isDebugEnabled())
            {
                if (result.getFailure() != null)
                    LOG.debug("General Failure", result.getFailure());
                if (result.getRequestFailure() != null)
                    LOG.debug("Request Failure", result.getRequestFailure());
                if (result.getResponseFailure() != null)
                    LOG.debug("Response Failure", result.getResponseFailure());
            }

            Throwable failure = result.getFailure();
            if ((failure instanceof java.net.SocketException) ||
                (failure instanceof java.io.InterruptedIOException) ||
                (failure instanceof HttpResponseException) ||
                (failure instanceof UpgradeException))
            {
                // handle as-is
                handleException(failure);
            }
            else
            {
                // wrap in UpgradeException
                handleException(new UpgradeException(requestURI, responseStatusCode, responseLine, failure));
            }
        }

        // TODO: this will be a 200 response for HTTP/2 success
        if (responseStatusCode != HttpStatus.SWITCHING_PROTOCOLS_101)
        {
            // Failed to upgrade (other reason)
            handleException( new UpgradeException(requestURI, responseStatusCode,
                    "Failed to upgrade to websocket: Unexpected HTTP Response Status Code: " + responseLine));
        }
    }

    protected void handleException(Throwable failure)
    {
        futureCoreSession.completeExceptionally(failure);
    }

    @SuppressWarnings("Duplicates")
    @Override
    public void upgrade(HttpResponse response, HttpConnectionOverHTTP httpConnection)
    {
        // TODO: http2 upgrade does not use upgrade header
        if (!this.getHeaders().get(HttpHeader.UPGRADE).equalsIgnoreCase("websocket"))
            throw new HttpResponseException("Not a WebSocket Upgrade", response);

        // TODO: http2 upgrade does not use SEC_WEBSOCKET_KEY or SEC_WEBSOCKET_ACCEPT
        // Check the Accept hash
        String reqKey = this.getHeaders().get(HttpHeader.SEC_WEBSOCKET_KEY);
        String expectedHash = WebSocketCore.hashKey(reqKey);
        String respHash = response.getHeaders().get(HttpHeader.SEC_WEBSOCKET_ACCEPT);
        if (expectedHash.equalsIgnoreCase(respHash) == false)
            throw new HttpResponseException("Invalid Sec-WebSocket-Accept hash (was:" + respHash + ", expected:" + expectedHash + ")", response);

        // Parse the Negotiated Extensions
        List<ExtensionConfig> negotiatedExtensions = new ArrayList<>();
        HttpField extField = response.getHeaders().getField(HttpHeader.SEC_WEBSOCKET_EXTENSIONS);
        if (extField != null)
        {
            String[] extValues = extField.getValues();
            if (extValues != null)
            {
                for (String extVal : extValues)
                {
                    QuotedStringTokenizer tok = new QuotedStringTokenizer(extVal, ",");
                    while (tok.hasMoreTokens())
                    {
                        negotiatedExtensions.add(ExtensionConfig.parse(tok.nextToken()));
                    }
                }
            }
        }

        // Verify the Negotiated Extensions
        List<ExtensionConfig> offeredExtensions = getExtensions();
        for (ExtensionConfig config : negotiatedExtensions)
        {
            if (config.getName().startsWith("@"))
                continue;

            long numMatch = offeredExtensions.stream().filter(c -> config.getName().equalsIgnoreCase(c.getName())).count();
            if (numMatch < 1)
                throw new WebSocketException("Upgrade failed: Sec-WebSocket-Extensions contained extension not requested");

            numMatch = negotiatedExtensions.stream().filter(c -> config.getName().equalsIgnoreCase(c.getName())).count();
            if (numMatch > 1)
                throw new WebSocketException("Upgrade failed: Sec-WebSocket-Extensions contained more than one extension of the same name");
        }

        // Negotiate the extension stack
        HttpClient httpClient = wsClient.getHttpClient();
        ExtensionStack extensionStack = new ExtensionStack(wsClient.getExtensionRegistry(), Behavior.CLIENT);
        extensionStack.negotiate(wsClient.getObjectFactory(), httpClient.getByteBufferPool(), offeredExtensions, negotiatedExtensions);

        // Get the negotiated subprotocol
        String negotiatedSubProtocol = null;
        HttpField subProtocolField = response.getHeaders().getField(HttpHeader.SEC_WEBSOCKET_SUBPROTOCOL);
        if (subProtocolField != null)
        {
            String values[] = subProtocolField.getValues();
            if (values != null)
            {
                if (values.length > 1)
                    throw new WebSocketException("Upgrade failed: Too many WebSocket subprotocol's in response: " + values);
                else if (values.length == 1)
                    negotiatedSubProtocol = values[0];
            }
        }

        // Verify the negotiated subprotocol
        List<String> offeredSubProtocols = getSubProtocols();
        if (negotiatedSubProtocol == null && !offeredSubProtocols.isEmpty())
            throw new WebSocketException("Upgrade failed: no subprotocol selected from offered subprotocols ");
        if (negotiatedSubProtocol != null && !offeredSubProtocols.contains(negotiatedSubProtocol))
            throw new WebSocketException("Upgrade failed: subprotocol [" + negotiatedSubProtocol + "] not found in offered subprotocols " + offeredSubProtocols);

        // We can upgrade
        EndPoint endp = httpConnection.getEndPoint();
        customize(endp);
        FrameHandler frameHandler = getFrameHandler(wsClient, response);

        if (frameHandler == null)
        {
            StringBuilder err = new StringBuilder();
            err.append("FrameHandler is null for request ").append(this.getURI().toASCIIString());
            if (negotiatedSubProtocol != null)
            {
                err.append(" [subprotocol: ").append(negotiatedSubProtocol).append("]");
            }
            throw new WebSocketException(err.toString());
        }

        Request request = response.getRequest();
        Negotiated negotiated = new Negotiated(
            request.getURI(),
            negotiatedSubProtocol,
            HttpScheme.HTTPS.is(request.getScheme()), // TODO better than this?
            extensionStack,
            WebSocketConstants.SPEC_VERSION_STRING);

        WebSocketChannel wsChannel = newWebSocketChannel(frameHandler, negotiated);
        wsClient.customize(wsChannel);

        WebSocketConnection wsConnection = newWebSocketConnection(endp, httpClient.getExecutor(), httpClient.getByteBufferPool(), wsChannel);

        for (Connection.Listener listener : wsClient.getBeans(Connection.Listener.class))
            wsConnection.addListener(listener);

        wsChannel.setWebSocketConnection(wsConnection);

        notifyUpgradeListeners((listener) -> listener.onHandshakeResponse(this, response));

        // Now swap out the connection
        try
        {
            endp.upgrade(wsConnection);
            futureCoreSession.complete(wsChannel);
        }
        catch (Throwable t)
        {
            futureCoreSession.completeExceptionally(t);
        }
    }

    /**
     * Allow for overridden customization of endpoint (such as special transport level properties: e.g. TCP keepAlive)
     *
     * @see <a href="https://github.com/eclipse/jetty.project/issues/1811">Issue #1811 - Customization of WebSocket Connections via WebSocketPolicy</a>
     */
    protected void customize(EndPoint endp)
    {
    }

    protected WebSocketConnection newWebSocketConnection(EndPoint endp, Executor executor, ByteBufferPool byteBufferPool, WebSocketChannel wsChannel)
    {
        return new WebSocketConnection(endp, executor, byteBufferPool, wsChannel);
    }

    protected WebSocketChannel newWebSocketChannel(FrameHandler handler, Negotiated negotiated)
    {
        return new WebSocketChannel(handler, Behavior.CLIENT, negotiated);
    }

    public abstract FrameHandler getFrameHandler(WebSocketCoreClient coreClient, HttpResponse response);

    private final String genRandomKey()
    {
        byte[] bytes = new byte[16];
        ThreadLocalRandom.current().nextBytes(bytes);
        return new String(B64Code.encode(bytes));
    }

    private void initWebSocketHeaders()
    {
        method(HttpMethod.GET);
        version(HttpVersion.HTTP_1_1);

        // The Upgrade Headers
        setHeaderIfNotPresent(HttpHeader.UPGRADE, "websocket");
        setHeaderIfNotPresent(HttpHeader.CONNECTION, "Upgrade");

        // The WebSocket Headers
        setHeaderIfNotPresent(HttpHeader.SEC_WEBSOCKET_KEY, genRandomKey());
        setHeaderIfNotPresent(HttpHeader.SEC_WEBSOCKET_VERSION, WebSocketConstants.SPEC_VERSION_STRING);

        // (Per the hybi list): Add no-cache headers to avoid compatibility issue.
        // There are some proxies that rewrite "Connection: upgrade"
        // to "Connection: close" in the response if a request doesn't contain
        // these headers.
        setHeaderIfNotPresent(HttpHeader.PRAGMA, "no-cache");
        setHeaderIfNotPresent(HttpHeader.CACHE_CONTROL, "no-cache");

        // Notify upgrade hooks
        notifyUpgradeListeners((listener) -> listener.onHandshakeRequest(this));
    }

    private void setHeaderIfNotPresent(HttpHeader header, String value)
    {
        if (!getHeaders().contains(header))
        {
            getHeaders().put(header, value);
        }
    }

    private void notifyUpgradeListeners(Consumer<UpgradeListener> action)
    {
        for (UpgradeListener listener : upgradeListeners)
        {
            try
            {
                action.accept(listener);
            }
            catch (Throwable t)
            {
                LOG.warn("Unhandled error: " + t.getMessage(), t);
            }
        }
    }
}
