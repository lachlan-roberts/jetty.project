package org.eclipse.jetty.websocket.core.server.internal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.BadMessageException;
import org.eclipse.jetty.io.ByteBufferPool;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.util.DecoratedObjectFactory;
import org.eclipse.jetty.websocket.core.WebSocketExtensionRegistry;
import org.eclipse.jetty.websocket.core.server.Negotiation;

// TODO: remove and inline the check
public class RFC8441Negotiation extends Negotiation
{
    public RFC8441Negotiation(Request baseRequest, HttpServletRequest request, HttpServletResponse response, WebSocketExtensionRegistry registry, DecoratedObjectFactory objectFactory, ByteBufferPool bufferPool) throws BadMessageException
    {
        super(baseRequest, request, response, registry, objectFactory, bufferPool);
    }

    @Override
    public boolean isUpgrade()
    {
        if (!baseRequest.hasMetaData())
            return false;

        return "websocket".equals(baseRequest.getMetaData().getProtocol());
    }
}
