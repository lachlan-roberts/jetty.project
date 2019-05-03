package org.eclipse.jetty.websocket.core.server.internal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.websocket.core.FrameHandler;
import org.eclipse.jetty.websocket.core.server.Handshaker;
import org.eclipse.jetty.websocket.core.server.WebSocketNegotiator;

public class HandshakerSelector implements Handshaker
{
    private List<Handshaker> handshakers = new ArrayList<>();

    // todo remove
    public HandshakerSelector(Handshaker ...handshakers)
    {
        for (Handshaker handshaker : handshakers)
        {
            this.handshakers.add(handshaker);
        }
    }

    @Override
    public boolean upgradeRequest(WebSocketNegotiator negotiator, HttpServletRequest request, HttpServletResponse response, FrameHandler.Customizer defaultCustomizer) throws IOException
    {
        // TODO: optimise (do pre checks and avoid iterating through handshakers)
        // TODO: minimum simplest thing to do to return false
        for (Handshaker handshaker : handshakers)
        {
            if (handshaker.upgradeRequest(negotiator, request, response, defaultCustomizer))
                return true;

            if (response.isCommitted())
                return false;
        }

        return false;
    }
}
