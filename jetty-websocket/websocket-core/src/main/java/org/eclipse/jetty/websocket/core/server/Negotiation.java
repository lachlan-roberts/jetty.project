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

package org.eclipse.jetty.websocket.core.server;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.BadMessageException;
import org.eclipse.jetty.http.HttpField;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.QuotedCSV;
import org.eclipse.jetty.io.ByteBufferPool;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.util.DecoratedObjectFactory;
import org.eclipse.jetty.websocket.core.Behavior;
import org.eclipse.jetty.websocket.core.ExtensionConfig;
import org.eclipse.jetty.websocket.core.WebSocketExtensionRegistry;
import org.eclipse.jetty.websocket.core.internal.ExtensionStack;

public class Negotiation
{
    protected final Request baseRequest;
    protected final HttpServletRequest request;
    protected final HttpServletResponse response;
    protected final List<ExtensionConfig> offeredExtensions;
    protected final List<String> offeredSubprotocols;
    protected final WebSocketExtensionRegistry registry;
    protected final DecoratedObjectFactory objectFactory;
    protected final ByteBufferPool bufferPool;
    protected final String version;
    protected final Boolean upgrade;
    protected final String key;

    protected List<ExtensionConfig> negotiatedExtensions;
    protected String subprotocol;
    protected ExtensionStack extensionStack;

    /**
     * @throws BadMessageException if there is any errors parsing the upgrade request
     */
    public Negotiation(
        Request baseRequest,
        HttpServletRequest request,
        HttpServletResponse response,
        WebSocketExtensionRegistry registry,
        DecoratedObjectFactory objectFactory,
        ByteBufferPool bufferPool) throws BadMessageException
    {
        this.baseRequest = baseRequest;
        this.request = request;
        this.response = response;
        this.registry = registry;
        this.objectFactory = objectFactory;
        this.bufferPool = bufferPool;

        Boolean upgradeHeader = null;
        String key = null;
        String version = null;
        QuotedCSV connectionCSVs = null;
        QuotedCSV extensions = null;
        QuotedCSV subprotocols = null;

        try
        {
            for (HttpField field : baseRequest.getHttpFields())
            {
                if (field.getHeader() != null)
                {
                    switch (field.getHeader())
                    {
                        case UPGRADE:
                            if (upgradeHeader == null && "websocket".equalsIgnoreCase(field.getValue()))
                                upgradeHeader = Boolean.TRUE;
                            break;

                        case CONNECTION:
                            if (connectionCSVs == null)
                                connectionCSVs = new QuotedCSV();
                            connectionCSVs.addValue(field.getValue());
                            break;

                        case SEC_WEBSOCKET_KEY:
                            key = field.getValue();
                            break;

                        case SEC_WEBSOCKET_VERSION:
                            version = field.getValue();
                            break;

                        case SEC_WEBSOCKET_EXTENSIONS:
                            if (extensions == null)
                                extensions = new QuotedCSV(field.getValue());
                            else
                                extensions.addValue(field.getValue());
                            break;

                        case SEC_WEBSOCKET_SUBPROTOCOL:
                            if (subprotocols == null)
                                subprotocols = new QuotedCSV(field.getValue());
                            else
                                subprotocols.addValue(field.getValue());
                            break;

                        default:
                    }
                }
            }

            this.version = version;
            this.key = key;

            this.upgrade = upgradeHeader != null && connectionCSVs != null && connectionCSVs.getValues().stream().anyMatch(s -> s.equalsIgnoreCase("Upgrade"));

            Set<String> available = registry.getAvailableExtensionNames();
            offeredExtensions = extensions == null
                    ? Collections.emptyList()
                    : extensions.getValues().stream()
                    .map(ExtensionConfig::parse)
                    .filter(ec -> available.contains(ec.getName().toLowerCase()) && !ec.getName().startsWith("@"))
                    .collect(Collectors.toList());

            offeredSubprotocols = subprotocols == null
                    ? Collections.emptyList()
                    : subprotocols.getValues();

            negotiatedExtensions = new ArrayList<>();
            for (ExtensionConfig config : offeredExtensions)
            {
                long matches = negotiatedExtensions.stream()
                        .filter(negotiatedConfig -> negotiatedConfig.getName().equals(config.getName())).count();
                if (matches == 0)
                    negotiatedExtensions.add(config);
            }
        }
        catch (Throwable t)
        {
            throw new BadMessageException("Invalid Handshake Request", t);
        }
    }

    public String getKey()
    {
        return key;
    }

    public List<ExtensionConfig> getOfferedExtensions()
    {
        return offeredExtensions;
    }

    public void setNegotiatedExtensions(List<ExtensionConfig> extensions)
    {
        if (extensions == offeredExtensions)
            return;
        negotiatedExtensions = extensions == null?null:new ArrayList<>(extensions);
        extensionStack = null;
    }

    public List<ExtensionConfig> getNegotiatedExtensions()
    {
        return negotiatedExtensions;
    }

    public List<String> getOfferedSubprotocols()
    {
        return offeredSubprotocols;
    }

    public Request getBaseRequest()
    {
        return baseRequest;
    }

    public HttpServletRequest getRequest()
    {
        return request;
    }

    public HttpServletResponse getResponse()
    {
        return response;
    }

    public void setSubprotocol(String subprotocol)
    {
        this.subprotocol = subprotocol;
        response.setHeader(HttpHeader.SEC_WEBSOCKET_SUBPROTOCOL.asString(), subprotocol);
    }

    public String getSubprotocol()
    {
        return subprotocol;
    }

    public String getVersion()
    {
        return version;
    }

    public boolean isUpgrade()
    {
        return upgrade;
    }

    public ExtensionStack getExtensionStack()
    {
        if (extensionStack == null)
        {
            // Extension stack can decide to drop any of these extensions or their parameters
            extensionStack = new ExtensionStack(registry, Behavior.SERVER);
            extensionStack.negotiate(objectFactory, bufferPool, offeredExtensions, negotiatedExtensions);
            negotiatedExtensions = extensionStack.getNegotiatedExtensions();

            if (extensionStack.hasNegotiatedExtensions())
                baseRequest.getResponse().setHeader(HttpHeader.SEC_WEBSOCKET_EXTENSIONS,
                    ExtensionConfig.toHeaderValue(negotiatedExtensions));
            else
                baseRequest.getResponse().setHeader(HttpHeader.SEC_WEBSOCKET_EXTENSIONS, null);
        }

        return extensionStack;
    }

    @Override
    public String toString()
    {
        return String.format("Negotiation@%x{uri=%s,oe=%s,op=%s}",
            hashCode(),
            getRequest().getRequestURI(),
            getOfferedExtensions(),
            getOfferedSubprotocols());
    }
}
