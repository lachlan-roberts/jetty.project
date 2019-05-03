package org.eclipse.jetty.http2.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.jetty.http2.IStream;
import org.eclipse.jetty.http2.api.Stream;
import org.eclipse.jetty.http2.frames.DataFrame;
import org.eclipse.jetty.io.AbstractEndPoint;
import org.eclipse.jetty.util.BufferUtil;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.thread.ScheduledExecutorScheduler;

public class EndpointOverHttp2 extends AbstractEndPoint
{
    private static final int BUFFER_SIZE = 1024; // TODO: configured from session

    private HttpTransportOverHTTP2 transport;
    private IStream http2Stream;

    private InetSocketAddress local;
    private InetSocketAddress remote;

    private ByteBuffer writeBuffer;

    private DataFrame frame;
    private Callback callback;
    private AtomicReference<State> writeReady = new AtomicReference<>(State.IDLE);

    private enum State
    {
        IDLE,
        FLUSHING,
        PENDING
    }

    public EndpointOverHttp2(HttpTransportOverHTTP2 transport, IStream stream, InetSocketAddress local, InetSocketAddress remote)
    {
        super(new ScheduledExecutorScheduler());
        this.transport = transport;

        this.http2Stream = stream;
        this.local = local;
        this.remote = remote;

        this.writeBuffer = ByteBuffer.allocate(BUFFER_SIZE); // TODO: use the ByteBufferPool

        stream.setListener(new Stream.Listener.Adapter()
        {
            // TODO: should we override other methods on this (maybe for failures)

            @Override
            public void onData(Stream stream, DataFrame frame, Callback callback)
            {
                EndpointOverHttp2.this.frame = frame;
                EndpointOverHttp2.this.callback = callback;
            }
        });
    }

    @Override
    public InetSocketAddress getLocalAddress()
    {
        return local;
    }

    @Override
    public InetSocketAddress getRemoteAddress()
    {
        return remote;
    }

    @Override
    public Object getTransport()
    {
        return transport;
    }

    @Override
    protected void onIncompleteFlush()
    {
        while (true)
        {
            switch (writeReady.get())
            {
                case IDLE:
                    getWriteFlusher().completeWrite();
                    break;

                case FLUSHING:
                    if (!writeReady.compareAndSet(State.FLUSHING, State.PENDING))
                        continue;
                    break;

                case PENDING:
                    throw new IllegalStateException();
            }

            break;
        }
    }

    @Override
    protected void needsFillInterest() throws IOException
    {
        //getFillInterest().fillable();

        Callback succeedFrame = callback;
        frame = null;
        callback = null;
        succeedFrame.succeeded();
    }

    @Override
    public int fill(ByteBuffer buffer) throws IOException
    {
        return BufferUtil.put(frame.getData(), buffer);
    }

    @Override
    public boolean flush(ByteBuffer... buffer) throws IOException
    {
        if (!writeReady.compareAndSet(State.IDLE, State.FLUSHING))
            return false;

        boolean incomplete = false;
        BufferUtil.clearToFill(writeBuffer);
        for (ByteBuffer bb : buffer)
        {
            int filled = BufferUtil.put(bb, writeBuffer);
            if (filled == 0)
            {
                incomplete = true;
                break;
            }
        }
        BufferUtil.flipToFlush(writeBuffer, 0);

        DataFrame frame = new DataFrame(http2Stream.getId(), writeBuffer, false);
        http2Stream.data(frame, Callback.from(()->
        {
            while(true)
            {
                switch (writeReady.get())
                {
                    case IDLE:
                        throw new IllegalStateException();

                    case FLUSHING:
                        if (!writeReady.compareAndSet(State.FLUSHING, State.IDLE))
                            continue;
                        break;

                    case PENDING:
                        if (!writeReady.compareAndSet(State.PENDING, State.IDLE))
                            continue;
                        getWriteFlusher().completeWrite();
                        break;
                }

                break;
            }
        }, t->close(t)));

        return incomplete;
    }
}