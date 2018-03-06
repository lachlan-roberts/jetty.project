//
//  ========================================================================
//  Copyright (c) 1995-2018 Mort Bay Consulting Pty. Ltd.
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

package org.eclipse.jetty.server;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.servlet.DispatcherType;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.io.ByteBufferPool;
import org.eclipse.jetty.io.LeakTrackingByteBufferPool;
import org.eclipse.jetty.io.MappedByteBufferPool;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.toolchain.test.MavenTestingUtils;
import org.eclipse.jetty.toolchain.test.TestTracker;
import org.eclipse.jetty.util.IO;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.eclipse.jetty.util.thread.Scheduler;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ThreadStarvationTest
{
    final static int BUFFER_SIZE=1024*1024;
    final static int BUFFERS=64;
    final static int THREADS=5;
    final static int CLIENTS=THREADS+2;
    @Rule
    public TestTracker tracker = new TestTracker();
    
    interface ConnectorProvider {
        ServerConnector newConnector(Server server, int acceptors, int selectors);
    }
    
    interface ClientSocketProvider {
        Socket newSocket(String host, int port) throws IOException;
    }
    
    @Parameterized.Parameters(name = "{0}")
    public static List<Object[]> params()
    {
        List<Object[]> params = new ArrayList<>();
        
        // HTTP
        ConnectorProvider http = (server, acceptors, selectors) -> new ServerConnector(server, acceptors, selectors);
        ClientSocketProvider httpClient = (host, port) -> new Socket(host, port);
        params.add(new Object[]{ "http", http, httpClient });
        
        // HTTPS/SSL/TLS
        ConnectorProvider https = (server, acceptors, selectors) -> {
            Path keystorePath = MavenTestingUtils.getTestResourcePath("keystore");
            SslContextFactory sslContextFactory = new SslContextFactory();
            sslContextFactory.setKeyStorePath(keystorePath.toString());
            sslContextFactory.setKeyStorePassword("storepwd");
            sslContextFactory.setKeyManagerPassword("keypwd");
            sslContextFactory.setTrustStorePath(keystorePath.toString());
            sslContextFactory.setTrustStorePassword("storepwd");
            ByteBufferPool pool = new LeakTrackingByteBufferPool(new MappedByteBufferPool.Tagged());
    
            HttpConnectionFactory httpConnectionFactory = new HttpConnectionFactory();
            ServerConnector connector = new ServerConnector(server,(Executor)null,(Scheduler)null,
                    pool, acceptors, selectors,
                    AbstractConnectionFactory.getFactories(sslContextFactory,httpConnectionFactory));
            SecureRequestCustomizer secureRequestCustomer = new SecureRequestCustomizer();
            secureRequestCustomer.setSslSessionAttribute("SSL_SESSION");
            httpConnectionFactory.getHttpConfiguration().addCustomizer(secureRequestCustomer);
            return connector;
        };
        ClientSocketProvider httpsClient = new ClientSocketProvider()
        {
            private SSLContext sslContext;
            {
                try
                {
                    HttpsURLConnection.setDefaultHostnameVerifier((hostname, session)-> true);
                    sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(null, SslContextFactory.TRUST_ALL_CERTS, new java.security.SecureRandom());
                    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
                }
                catch(Exception e)
                {
                    e.printStackTrace();
                    throw new RuntimeException(e);
                }
            }
            
            @Override
            public Socket newSocket(String host, int port) throws IOException
            {
                return sslContext.getSocketFactory().createSocket(host,port);
            }
        };
        params.add(new Object[]{ "https/ssl/tls", https, httpsClient });
        
        return params;
    }
    
    private final ConnectorProvider connectorProvider;
    private final ClientSocketProvider clientSocketProvider;
    private QueuedThreadPool _threadPool;
    private Server _server;
    private ServerConnector _connector;
    
    public ThreadStarvationTest(String testType, ConnectorProvider connectorProvider, ClientSocketProvider clientSocketProvider)
    {
        this.connectorProvider = connectorProvider;
        this.clientSocketProvider = clientSocketProvider;
    }
    
    private Server prepareServer(Handler handler)
    {
        _threadPool = new QueuedThreadPool();
        _threadPool.setMinThreads(THREADS);
        _threadPool.setMaxThreads(THREADS);
        _threadPool.setDetailedDump(true);
        _server = new Server(_threadPool);
        int acceptors = 1;
        int selectors = 1;
        _connector = connectorProvider.newConnector(_server, acceptors, selectors);
        _server.addConnector(_connector);
        _server.setHandler(handler);
        return _server;
    }

    @After
    public void dispose() throws Exception
    {
        _server.stop();
    }

    @Test
    public void testReadInput() throws Exception
    {
        prepareServer(new ReadHandler()).start();

        try(Socket client = clientSocketProvider.newSocket("localhost", _connector.getLocalPort()))
        {
            client.setSoTimeout(10000);
            OutputStream os = client.getOutputStream();
            InputStream is = client.getInputStream();
    
            String request = "" +
                    "GET / HTTP/1.0\r\n" +
                    "Host: localhost\r\n" +
                    "Content-Length: 10\r\n" +
                    "\r\n" +
                    "0123456789\r\n";
            os.write(request.getBytes(StandardCharsets.UTF_8));
            os.flush();
    
            String response = IO.toString(is);
            assertEquals(-1, is.read());
            assertThat(response, containsString("200 OK"));
            assertThat(response, containsString("Read Input 10"));
        }
    }

    @Test
    public void testReadStarvation() throws Exception
    {
        prepareServer(new ReadHandler());
        _server.start();
    
        ExecutorService clientExecutors = Executors.newFixedThreadPool(CLIENTS);
        
        List<Callable<String>> clientTasks = new ArrayList<>();
        
        for(int i=0; i<CLIENTS; i++) {
            clientTasks.add(() ->
            {
                try (Socket client = clientSocketProvider.newSocket("localhost", _connector.getLocalPort());
                     OutputStream out = client.getOutputStream();
                     InputStream in = client.getInputStream())
                {
                    client.setSoTimeout(10000);

                    String request = "" +
                            "PUT / HTTP/1.0\r\n" +
                            "host: localhost\r\n" +
                            "content-length: 10\r\n" +
                            "\r\n" +
                            "1";
                    
                    // Write partial request
                    out.write(request.getBytes(StandardCharsets.UTF_8));
                    out.flush();
    
                    // Finish Request
                    Thread.sleep(1500);
                    out.write(("234567890\r\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    
                    // Read Response
                    String response = IO.toString(in);
                    assertEquals(-1, in.read());
                    return response;
                }
            });
        }
        
        try
        {
            List<Future<String>> responses = clientExecutors.invokeAll(clientTasks, 60, TimeUnit.SECONDS);
    
            for (Future<String> responseFut : responses)
            {
                String response = responseFut.get();
                assertThat(response, containsString("200 OK"));
                assertThat(response, containsString("Read Input 10"));
            }
        } finally
        {
            clientExecutors.shutdownNow();
        }
    }

    protected static class ReadHandler extends AbstractHandler
    {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
        {
            baseRequest.setHandled(true);
            
            if(request.getDispatcherType() == DispatcherType.REQUEST)
            {
                response.setStatus(200);
    
                int l = request.getContentLength();
                int r = 0;
                while (r < l)
                {
                    if (request.getInputStream().read() >= 0)
                        r++;
                }
    
                response.getOutputStream().write(("Read Input " + r + "\r\n").getBytes());
            }
            else
            {
                response.sendError(HttpStatus.INTERNAL_SERVER_ERROR_500);
            }
        }
    }
    

    @Test
    public void testWriteStarvation() throws Exception
    {
        prepareServer(new WriteHandler());
        _server.start();
    
        ExecutorService clientExecutors = Executors.newFixedThreadPool(CLIENTS);
    
        List<Callable<Long>> clientTasks = new ArrayList<>();
    
        for(int i=0; i<CLIENTS; i++) 
        {
            clientTasks.add(() ->
            {
                try (Socket client = clientSocketProvider.newSocket("localhost", _connector.getLocalPort());
                     OutputStream out = client.getOutputStream();
                     InputStream in = client.getInputStream())
                {
                    client.setSoTimeout(30000);
                
                    String request = "" +
                            "GET / HTTP/1.0\r\n" +
                            "host: localhost\r\n" +
                            "\r\n";
                
                    // Write GET request
                    out.write(request.getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    
                    TimeUnit.MILLISECONDS.sleep(1500);
                    
                    // Read Response
                    long bodyCount = 0;
                    long len;
                    
                    byte buf[] = new byte[1024];
                    
                    while((len = in.read(buf,0,buf.length)) != -1)
                    {
                        for(int x=0; x<len; x++)
                        {
                            if(buf[x] == '!') bodyCount++;
                        }
                    }
                    return bodyCount;
                }
            });
        }
    
        try
        {
            List<Future<Long>> responses = clientExecutors.invokeAll(clientTasks, 60, TimeUnit.SECONDS);
        
            long expected = BUFFERS * BUFFER_SIZE;
            for (Future<Long> responseFut : responses)
            {
                Long bodyCount = responseFut.get();
                assertThat(bodyCount.longValue(), is(expected));
            }
        } 
        finally
        {
            clientExecutors.shutdownNow();
        }
    }

    protected static class WriteHandler extends AbstractHandler
    {
        byte[] content=new byte[BUFFER_SIZE];
        {
            // Using a character that will not show up in a HTTP response header
            Arrays.fill(content,(byte)'!');
        }
        
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
        {
            baseRequest.setHandled(true);
            response.setStatus(200);

            response.setContentLength(BUFFERS*BUFFER_SIZE);
            OutputStream out = response.getOutputStream();
            for (int i=0;i<BUFFERS;i++)
            {
                out.write(content);
                out.flush();
            }
        }
    }
}
