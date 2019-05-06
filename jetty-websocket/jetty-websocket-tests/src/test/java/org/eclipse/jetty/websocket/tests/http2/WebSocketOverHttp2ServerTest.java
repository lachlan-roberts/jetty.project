package org.eclipse.jetty.websocket.tests.http2;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.jetty.http.HostPortHttpField;
import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpScheme;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http.MetaData;
import org.eclipse.jetty.http2.api.Session;
import org.eclipse.jetty.http2.api.Stream;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.frames.DataFrame;
import org.eclipse.jetty.http2.frames.HeadersFrame;
import org.eclipse.jetty.http2.server.HTTP2CServerConnectionFactory;
import org.eclipse.jetty.io.ByteBufferPool;
import org.eclipse.jetty.io.MappedByteBufferPool;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.BlockingArrayQueue;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.FuturePromise;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.eclipse.jetty.websocket.core.Frame;
import org.eclipse.jetty.websocket.core.OpCode;
import org.eclipse.jetty.websocket.core.internal.Generator;
import org.eclipse.jetty.websocket.core.internal.Parser;
import org.eclipse.jetty.websocket.server.JettyWebSocketServlet;
import org.eclipse.jetty.websocket.server.JettyWebSocketServletContainerInitializer;
import org.eclipse.jetty.websocket.server.JettyWebSocketServletFactory;
import org.eclipse.jetty.websocket.tests.EchoSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class WebSocketOverHttp2ServerTest
{
    public static class MyWebSocketServlet extends JettyWebSocketServlet
    {
        @Override
        public void configure(JettyWebSocketServletFactory factory)
        {
            factory.addMapping("/",(req, resp)->new EchoSocket());
        }
    }

    private static final Logger LOG = Log.getLogger(WebSocketOverHttp2ServerTest.class);

    private Server server;
    private ServerConnector connector;
    private HTTP2Client http2Client;
    private ByteBufferPool bufferPool = new MappedByteBufferPool();
    private Generator generator = new Generator(bufferPool);
    private Parser parser = new Parser(bufferPool);

    @BeforeEach
    public void before() throws Exception
    {
        server = new Server();
        HTTP2CServerConnectionFactory factory = new HTTP2CServerConnectionFactory(new HttpConfiguration());
        factory.setExtendedConnectSupported(true);
        connector = new ServerConnector(server, 1, 1, factory);
        server.addConnector(connector);

        ServletContextHandler contextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        contextHandler.setContextPath("/");
        server.setHandler(contextHandler);
        contextHandler.addServlet(MyWebSocketServlet.class, "/");
        JettyWebSocketServletContainerInitializer.configureContext(contextHandler);

        server.start();

        http2Client = new HTTP2Client();
        http2Client.start();
    }

    @AfterEach
    public void after() throws Exception
    {
        http2Client.stop();
        server.stop();
    }

    @Test
    public void test() throws Exception
    {
        FuturePromise<Session> sessionPromise = new FuturePromise<>();
        http2Client.connect(new InetSocketAddress("localhost", connector.getLocalPort()), new Session.Listener.Adapter(), sessionPromise);

        Session session = sessionPromise.get(5, TimeUnit.SECONDS);
        HttpFields fields = new HttpFields();
        fields.add(HttpHeader.SEC_WEBSOCKET_VERSION, "13");
        MetaData.Request connectMetaData = new MetaData.Request(HttpMethod.CONNECT.asString(), HttpScheme.HTTP,
                new HostPortHttpField("localhost:"+connector.getLocalPort()), "/", HttpVersion.HTTP_2, fields);
        connectMetaData.setProtocol("websocket");
        HeadersFrame connect = new HeadersFrame(connectMetaData, null, false);

        BlockingArrayQueue<ByteBuffer> dataQueue = new BlockingArrayQueue<>();
        CountDownLatch headersLatch = new CountDownLatch(1);

        FuturePromise<Stream> streamPromise = new FuturePromise<>();
        session.newStream(connect, streamPromise, new Stream.Listener.Adapter()
        {
            @Override
            public void onHeaders(Stream stream, HeadersFrame frame)
            {
                LOG.info("onHeaders(): " + frame);
                MetaData.Response metaData = (MetaData.Response)frame.getMetaData();
                if (metaData.getStatus() == HttpStatus.OK_200)
                    headersLatch.countDown();
            }

            @Override
            public void onData(Stream stream, DataFrame frame, Callback callback)
            {
                LOG.info("onData(): " + frame);
                dataQueue.offer(frame.getData());
                callback.succeeded();
            }
        });

        ByteBuffer generatedFrame = generator.generateWholeFrame(new Frame(OpCode.TEXT, "hello world").setMask(new byte[]{0,0,0,0}));
        Stream stream = streamPromise.get(5, TimeUnit.SECONDS);
        assertTrue(headersLatch.await(5, TimeUnit.SECONDS));

        stream.data(new DataFrame(stream.getId(), generatedFrame, false), Callback.NOOP);
        ByteBuffer receivedData = dataQueue.poll(666, TimeUnit.SECONDS);
        Parser.ParsedFrame parsedFrame = parser.parse(receivedData);

        LOG.info("receivedFrame: " + parsedFrame);
        assertThat(parsedFrame.getOpCode(), is(OpCode.TEXT));
        assertThat(parsedFrame.getPayloadAsUTF8(), is("hello world"));

        generator.getBufferPool().release(generatedFrame);
    }
}
