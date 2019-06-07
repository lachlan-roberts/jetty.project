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

package org.eclipse.jetty.requestlog.jmh;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.eclipse.jetty.http.MetaData;
import org.eclipse.jetty.server.AbstractNCSARequestLog;
import org.eclipse.jetty.server.CustomRequestLog;
import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.component.ContainerLifeCycle;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@State(Scope.Benchmark)
@Threads(4)
@Warmup(iterations = 7, time = 500, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 7, time = 500, timeUnit = TimeUnit.MILLISECONDS)
public class CustomRequestLogBenchmark
{
    private static final String OLD = "OLD";
    private static final String NEW = "NEW";
    private static final int NUM_REQUESTS = 10000;
    public static List<ReqResp> requests = new ArrayList<>();

    public static class ReqResp
    {
        public final Request request;
        public final Response response;

        public ReqResp(Request request, Response response)
        {
            this.request = request;
            this.response = response;
        }
    }

    @Param({OLD, NEW})
    public static String requestLogType;
    public static LogWriterQueue logWriter = new LogWriterQueue();
    private static RequestLog requestLog;

    @Setup(Level.Trial)
    public static void setupTrial() throws Exception
    {
        for (int i = 0; i< NUM_REQUESTS; i++)
        {
            requests.add(new ReqResp(generateFakeRequest(), generateFakeResponse()));
        }

        switch (requestLogType)
        {
            case OLD:
                AbstractNCSARequestLog rl = new AbstractNCSARequestLog(logWriter);
                rl.setExtended(true);
                rl.setLogDateFormat(CustomRequestLog.DEFAULT_DATE_FORMAT);
                rl.start();
                requestLog = rl;
                break;

            case NEW:
                requestLog = new CustomRequestLog(logWriter, CustomRequestLog.EXTENDED_NCSA_FORMAT);
                break;

            default:
                throw new IllegalStateException();
        }

        ((ContainerLifeCycle)requestLog).start();
    }

    @TearDown(Level.Trial)
    public static void stopTrial() throws Exception
    {
        ((ContainerLifeCycle)requestLog).stop();
    }

    @Benchmark
    @BenchmarkMode({Mode.Throughput})
    public long customRequestLogBenchmark() throws Exception
    {
        long count = 0;
        for (ReqResp rr : requests)
        {
            requestLog.log(rr.request, rr.response);
            count += logWriter.getNextLog().length();
        }
        return count;
    }

    public static void main(String[] args) throws RunnerException
    {
        Options opt = new OptionsBuilder()
                .include(CustomRequestLogBenchmark.class.getSimpleName())
                .warmupIterations(20)
                .measurementIterations(10)
                .forks(1)
                .threads(1)
                .build();

        new Runner(opt).run();
    }

    public static class LogWriterQueue implements RequestLog.Writer
    {
        Queue<String> logs = new ArrayDeque<>();

        public String getNextLog()
        {
            return logs.poll();
        }

        @Override
        public void write(String requestEntry) throws IOException
        {
            logs.add(requestEntry);
        }
    }

    static Request generateFakeRequest()
    {
        Random rand = new Random();
        String referer = "referer"+rand.nextInt(9999);
        String userAgent = "userAgent"+rand.nextInt(9999);


        Request request = new Request(null, null)
        {
            @Override
            public String getOriginalURI()
            {
                return "localhost";
            }

            @Override
            public String getProtocol()
            {
                return "HTTP/1.1";
            }

            @Override
            public String getMethod()
            {
                return "GET";
            }

            @Override
            public String getHeader(String name)
            {
                if (name.equalsIgnoreCase("Referer"))
                {
                    return referer;
                }
                else if (name.equalsIgnoreCase("User-Agent"))
                {
                    return userAgent;
                }

                return null;
            }
        };
        request.setRemoteAddr(new InetSocketAddress("localhost", + (rand.nextInt(7000)+1001)));
        request.setTimeStamp(System.currentTimeMillis());

        return request;
    }


    static Response generateFakeResponse()
    {
        Random rand = new Random();
        MetaData.Response metaData = new MetaData.Response();
        metaData.setStatus(200);
        long bytesWritten = rand.nextInt(9999999);

        HttpChannel channel = new HttpChannel(null, new HttpConfiguration(), null, null)
        {
            @Override
            public long getBytesWritten()
            {
                return bytesWritten;
            }
        };

        Response response = new Response(null, null)
        {
            @Override
            public MetaData.Response getCommittedMetaData()
            {
                return metaData;
            }

            @Override
            public HttpChannel getHttpChannel()
            {
                return channel;
            }
        };

        return response;
    }
}


