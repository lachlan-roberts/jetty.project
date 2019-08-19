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

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.Cookie;

import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.QuotedCSV;
import org.eclipse.jetty.http.pathmap.PathMappings;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.RequestLogWriter;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.util.DateCache;
import org.eclipse.jetty.util.annotation.ManagedAttribute;
import org.eclipse.jetty.util.annotation.ManagedObject;
import org.eclipse.jetty.util.component.ContainerLifeCycle;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

import static java.lang.invoke.MethodHandles.dropArguments;
import static java.lang.invoke.MethodType.methodType;


@ManagedObject("Custom format request log")
public class CustomListRequestLog extends ContainerLifeCycle implements RequestLog
{
    protected static final Logger LOG = Log.getLogger(CustomListRequestLog.class);

    public static final String DEFAULT_DATE_FORMAT = "dd/MMM/yyyy:HH:mm:ss ZZZ";

    public static final String NCSA_FORMAT = "%{client}a - %u %t \"%r\" %s %O";
    public static final String EXTENDED_NCSA_FORMAT = "%{client}a - %u %t \"%r\" %s %O \"%{Referer}i\" \"%{User-Agent}i\"";

    private static ThreadLocal<StringBuilder> _buffers = ThreadLocal.withInitial(() -> new StringBuilder(256));

    private String[] _ignorePaths;
    private transient PathMappings<String> _ignorePathMap;

    private RequestLog.Writer _requestLogWriter;
    private final List<MethodHandle> _logHandles;
    private final String _formatString;

    public CustomListRequestLog(RequestLog.Writer writer, String formatString)
    {
        _formatString = formatString;
        _requestLogWriter = writer;
        addBean(_requestLogWriter);

        try
        {
            _logHandles = generateLogHandles(formatString);
        }
        catch (NoSuchMethodException e)
        {
            throw new IllegalStateException(e);
        }
        catch (IllegalAccessException e)
        {
            throw new IllegalStateException(e);
        }
    }

    public CustomListRequestLog(String file)
    {
        this(file, EXTENDED_NCSA_FORMAT);
    }

    public CustomListRequestLog(String file, String format)
    {
        this(new RequestLogWriter(file), format);
    }

    @ManagedAttribute("The RequestLogWriter")
    public RequestLog.Writer getWriter()
    {
        return _requestLogWriter;
    }

    /**
     * Writes the request and response information to the output stream.
     *
     * @see org.eclipse.jetty.server.RequestLog#log(Request, Response)
     */
    @Override
    public void log(Request request, Response response)
    {
        try
        {
            if (_ignorePathMap != null && _ignorePathMap.getMatch(request.getRequestURI()) != null)
                return;

            StringBuilder sb = _buffers.get();
            sb.setLength(0);

            for (MethodHandle methodHandle : _logHandles)
                methodHandle.invoke(sb, request, response);

            String log = sb.toString();
            _requestLogWriter.write(log);
        }
        catch (Throwable e)
        {
            LOG.warn(e);
        }
    }

    /**
     * Set request paths that will not be logged.
     *
     * @param ignorePaths array of request paths
     */
    public void setIgnorePaths(String[] ignorePaths)
    {
        _ignorePaths = ignorePaths;
    }

    /**
     * Retrieve the request paths that will not be logged.
     *
     * @return array of request paths
     */
    public String[] getIgnorePaths()
    {
        return _ignorePaths;
    }

    /**
     * Retrieve the format string.
     *
     * @return the format string
     */
    @ManagedAttribute("format string")
    public String getFormatString()
    {
        return _formatString;
    }

    /**
     * Set up request logging and open log file.
     *
     * @see org.eclipse.jetty.util.component.AbstractLifeCycle#doStart()
     */
    @Override
    protected synchronized void doStart() throws Exception
    {
        if (_ignorePaths != null && _ignorePaths.length > 0)
        {
            _ignorePathMap = new PathMappings<>();
            for (int i = 0; i < _ignorePaths.length; i++)
            {
                _ignorePathMap.put(_ignorePaths[i], _ignorePaths[i]);
            }
        }
        else
            _ignorePathMap = null;

        super.doStart();
    }

    private static void append(StringBuilder buf, String s)
    {
        if (s == null || s.length() == 0)
            buf.append('-');
        else
            buf.append(s);
    }

    private static void append(String s, StringBuilder buf)
    {
        append(buf, s);
    }

    private List<MethodHandle> generateLogHandles(String formatString) throws NoSuchMethodException, IllegalAccessException
    {
        MethodHandles.Lookup lookup = MethodHandles.lookup();
        MethodHandle append = lookup.findStatic(CustomListRequestLog.class, "append", methodType(Void.TYPE, String.class, StringBuilder.class));

        List<Token> tokens = getTokens(formatString);
        Collections.reverse(tokens);


        List<MethodHandle> methodHandles = new ArrayList<>();
        for (Token t : tokens)
        {
            if (t.isLiteralString())
                updateLogHandle(methodHandles, append, t.literal);
            else
                updateLogHandle(methodHandles, append, lookup, t.code, t.arg, t.modifiers, t.negated);
        }

        return methodHandles;
    }

    private static List<Token> getTokens(String formatString)
    {
        /*
        Extracts literal strings and percent codes out of the format string.
        We will either match a percent code of the format %MODIFIERS{PARAM}CODE, or a literal string
        until the next percent code or the end of the formatString is reached.

        where
            MODIFIERS is an optional comma separated list of numbers.
            {PARAM} is an optional string parameter to the percent code.
            CODE is a 1 to 2 character string corresponding to a format code.
         */
        final Pattern PATTERN = Pattern.compile("^(?:%(?<MOD>!?[0-9,]+)?(?:\\{(?<ARG>[^}]+)})?(?<CODE>(?:(?:ti)|(?:to)|[a-zA-Z%]))|(?<LITERAL>[^%]+))(?<REMAINING>.*)", Pattern.DOTALL | Pattern.MULTILINE);

        List<Token> tokens = new ArrayList<>();
        String remaining = formatString;
        while (remaining.length() > 0)
        {
            Matcher m = PATTERN.matcher(remaining);
            if (m.matches())
            {
                if (m.group("CODE") != null)
                {
                    String code = m.group("CODE");
                    String arg = m.group("ARG");
                    String modifierString = m.group("MOD");

                    Boolean negated = false;
                    if (modifierString != null)
                    {
                        if (modifierString.startsWith("!"))
                        {
                            modifierString = modifierString.substring(1);
                            negated = true;
                        }
                    }

                    List<String> modifiers = new QuotedCSV(modifierString).getValues();
                    tokens.add(new Token(code, arg, modifiers, negated));
                }
                else if (m.group("LITERAL") != null)
                {
                    String literal = m.group("LITERAL");
                    tokens.add(new Token(literal));
                }
                else
                {
                    throw new IllegalStateException("formatString parsing error");
                }

                remaining = m.group("REMAINING");
            }
            else
            {
                throw new IllegalArgumentException("Invalid format string");
            }
        }

        return tokens;
    }

    private static class Token
    {
        public final String code;
        public final String arg;
        public final List<String> modifiers;
        public final boolean negated;

        public final String literal;

        public Token(String code, String arg, List<String> modifiers, boolean negated)
        {
            this.code = code;
            this.arg = arg;
            this.modifiers = modifiers;
            this.negated = negated;

            this.literal = null;
        }

        public Token(String literal)
        {
            this.code = null;
            this.arg = null;
            this.modifiers = null;
            this.negated = false;

            this.literal = literal;
        }

        public boolean isLiteralString()
        {
            return (literal != null);
        }

        public boolean isPercentCode()
        {
            return (code != null);
        }
    }

    private void updateLogHandle(List<MethodHandle> methodHandles, MethodHandle append, String literal)
    {
        methodHandles.add(dropArguments(dropArguments(append.bindTo(literal), 1, Request.class), 2, Response.class));
    }

    //TODO use integer comparisons instead of strings
    private static boolean modify(List<String> modifiers, Boolean negated, StringBuilder b, Request request, Response response)
    {
        String responseCode = Integer.toString(response.getStatus());
        if (negated)
        {
            return (!modifiers.contains(responseCode));
        }
        else
        {
            return (modifiers.contains(responseCode));
        }
    }

    private void updateLogHandle(List<MethodHandle> methodHandles, MethodHandle append, MethodHandles.Lookup lookup, String code, String arg, List<String> modifiers, boolean negated) throws NoSuchMethodException, IllegalAccessException
    {
        MethodType logType = methodType(Void.TYPE, StringBuilder.class, Request.class, Response.class);
        MethodType logTypeArg = methodType(Void.TYPE, String.class, StringBuilder.class, Request.class, Response.class);

        //TODO should we throw IllegalArgumentExceptions when given arguments for codes which do not take them
        MethodHandle specificHandle;
        switch (code)
        {
            case "%":
            {
                specificHandle = dropArguments(dropArguments(append.bindTo("%"), 1, Request.class), 2, Response.class);
                break;
            }

            case "a":
            {
                if (arg == null || arg.isEmpty())
                    arg = "server";

                String method;
                switch (arg)
                {
                    case "server":
                        method = "logServerHost";
                        break;

                    case "client":
                        method = "logClientHost";
                        break;

                    case "local":
                        method = "logLocalHost";
                        break;

                    case "remote":
                        method = "logRemoteHost";
                        break;

                    default:
                        throw new IllegalArgumentException("Invalid arg for %a");
                }

                specificHandle = lookup.findStatic(CustomListRequestLog.class, method, logType);
                break;
            }

            case "p":
            {
                if (arg == null || arg.isEmpty())
                    arg = "server";

                String method;
                switch (arg)
                {

                    case "server":
                        method = "logServerPort";
                        break;

                    case "client":
                        method = "logClientPort";
                        break;

                    case "local":
                        method = "logLocalPort";
                        break;

                    case "remote":
                        method = "logRemotePort";
                        break;

                    default:
                        throw new IllegalArgumentException("Invalid arg for %p");
                }

                specificHandle = lookup.findStatic(CustomListRequestLog.class, method, logType);
                break;
            }

            case "I":
            {
                String method;
                if (arg == null || arg.isEmpty())
                    method = "logBytesReceived";
                else if (arg.equalsIgnoreCase("clf"))
                    method = "logBytesReceivedCLF";
                else
                    throw new IllegalArgumentException("Invalid argument for %I");

                specificHandle = lookup.findStatic(CustomListRequestLog.class, method, logType);
                break;
            }

            case "O":
            {
                String method;
                if (arg == null || arg.isEmpty())
                    method = "logBytesSent";
                else if (arg.equalsIgnoreCase("clf"))
                    method = "logBytesSentCLF";
                else
                    throw new IllegalArgumentException("Invalid argument for %O");

                specificHandle = lookup.findStatic(CustomListRequestLog.class, method, logType);
                break;
            }

            case "S":
            {
                String method;
                if (arg == null || arg.isEmpty())
                    method = "logBytesTransferred";
                else if (arg.equalsIgnoreCase("clf"))
                    method = "logBytesTransferredCLF";
                else
                    throw new IllegalArgumentException("Invalid argument for %S");

                specificHandle = lookup.findStatic(CustomListRequestLog.class, method, logType);
                break;
            }

            case "C":
            {
                if (arg == null || arg.isEmpty())
                {
                    specificHandle = lookup.findStatic(CustomListRequestLog.class, "logRequestCookies", logType);
                }
                else
                {
                    specificHandle = lookup.findStatic(CustomListRequestLog.class, "logRequestCookie", logTypeArg);
                    specificHandle = specificHandle.bindTo(arg);
                }
                break;
            }

            case "D":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logLatencyMicroseconds", logType);
                break;
            }

            case "e":
            {
                if (arg == null || arg.isEmpty())
                    throw new IllegalArgumentException("No arg for %e");

                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logEnvironmentVar", logTypeArg);
                specificHandle = specificHandle.bindTo(arg);
                break;
            }

            case "f":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logFilename", logType);
                break;
            }

            case "H":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logRequestProtocol", logType);
                break;
            }

            case "i":
            {
                if (arg == null || arg.isEmpty())
                    throw new IllegalArgumentException("No arg for %i");

                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logRequestHeader", logTypeArg);
                specificHandle = specificHandle.bindTo(arg);
                break;
            }

            case "k":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logKeepAliveRequests", logType);
                break;
            }

            case "m":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logRequestMethod", logType);
                break;
            }

            case "o":
            {
                if (arg == null || arg.isEmpty())
                    throw new IllegalArgumentException("No arg for %o");

                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logResponseHeader", logTypeArg);
                specificHandle = specificHandle.bindTo(arg);
                break;
            }

            case "q":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logQueryString", logType);
                break;
            }

            case "r":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logRequestFirstLine", logType);
                break;
            }

            case "R":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logRequestHandler", logType);
                break;
            }

            case "s":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logResponseStatus", logType);
                break;
            }

            case "t":
            {
                String format = DEFAULT_DATE_FORMAT;
                TimeZone timeZone = TimeZone.getTimeZone("GMT");
                Locale locale = Locale.getDefault();

                if (arg != null && !arg.isEmpty())
                {
                    String[] args = arg.split("\\|");
                    switch (args.length)
                    {
                        case 1:
                            format = args[0];
                            break;

                        case 2:
                            format = args[0];
                            timeZone = TimeZone.getTimeZone(args[1]);
                            break;

                        case 3:
                            format = args[0];
                            timeZone = TimeZone.getTimeZone(args[1]);
                            locale = Locale.forLanguageTag(args[2]);
                            break;

                        default:
                            throw new IllegalArgumentException("Too many \"|\" characters in %t");
                    }
                }

                DateCache logDateCache = new DateCache(format, locale, timeZone);

                MethodType logTypeDateCache = methodType(Void.TYPE, DateCache.class, StringBuilder.class, Request.class, Response.class);
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logRequestTime", logTypeDateCache);
                specificHandle = specificHandle.bindTo(logDateCache);
                break;
            }

            case "T":
            {
                if (arg == null)
                    arg = "s";

                String method;
                switch (arg)
                {
                    case "s":
                        method = "logLatencySeconds";
                        break;
                    case "us":
                        method = "logLatencyMicroseconds";
                        break;
                    case "ms":
                        method = "logLatencyMilliseconds";
                        break;
                    default:
                        throw new IllegalArgumentException("Invalid arg for %T");
                }

                specificHandle = lookup.findStatic(CustomListRequestLog.class, method, logType);
                break;
            }

            case "u":
            {
                String method;
                if (arg == null || arg.isEmpty())
                    method = "logRequestAuthenticationWithDeferred";
                else
                    method = "logRequestAuthentication";

                specificHandle = lookup.findStatic(CustomListRequestLog.class, method, logType);
                break;
            }

            case "U":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logUrlRequestPath", logType);
                break;
            }

            case "X":
            {
                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logConnectionStatus", logType);
                break;
            }

            case "ti":
            {
                if (arg == null || arg.isEmpty())
                    throw new IllegalArgumentException("No arg for %ti");

                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logRequestTrailer", logTypeArg);
                specificHandle = specificHandle.bindTo(arg);
                break;
            }

            case "to":
            {
                if (arg == null || arg.isEmpty())
                    throw new IllegalArgumentException("No arg for %to");

                specificHandle = lookup.findStatic(CustomListRequestLog.class, "logResponseTrailer", logTypeArg);
                specificHandle = specificHandle.bindTo(arg);
                break;
            }

            default:
                throw new IllegalArgumentException("Unsupported code %" + code);
        }


        if (modifiers != null && !modifiers.isEmpty())
        {
            MethodHandle modifierTest = lookup.findStatic(CustomListRequestLog.class, "modify", methodType(Boolean.TYPE, List.class, Boolean.class, StringBuilder.class, Request.class, Response.class));
            modifierTest = modifierTest.bindTo(modifiers).bindTo(negated);
            MethodHandle dash = dropArguments(dropArguments(append.bindTo("-"), 1, Request.class), 2, Response.class);
            methodHandles.add(MethodHandles.guardWithTest(modifierTest, specificHandle, dash));
            return;
        }

        methodHandles.add(specificHandle);
    }

    /**
     * Extract the user authentication
     *
     * @param request The request to extract from
     * @param checkDeferred Whether to check for deferred authentication
     * @return The string to log for authenticated user.
     */
    protected static String getAuthentication(Request request, boolean checkDeferred)
    {
        Authentication authentication = request.getAuthentication();

        String name = null;

        boolean deferred = false;
        if (checkDeferred && authentication instanceof Authentication.Deferred)
        {
            authentication = ((Authentication.Deferred)authentication).authenticate(request);
            deferred = true;
        }

        if (authentication instanceof Authentication.User)
            name = ((Authentication.User)authentication).getUserIdentity().getUserPrincipal().getName();

        return (name == null) ? null : (deferred ? ("?" + name) : name);
    }

    private static void logNothing(StringBuilder b, Request request, Response response)
    {
    }

    private static void logServerHost(StringBuilder b, Request request, Response response)
    {
        append(b, request.getServerName());
    }

    private static void logClientHost(StringBuilder b, Request request, Response response)
    {
        append(b, request.getRemoteHost());
    }

    private static void logLocalHost(StringBuilder b, Request request, Response response)
    {
        append(b, request.getHttpChannel().getEndPoint().getLocalAddress().getAddress().getHostAddress());
    }

    private static void logRemoteHost(StringBuilder b, Request request, Response response)
    {
        append(b, request.getHttpChannel().getEndPoint().getRemoteAddress().getAddress().getHostAddress());
    }

    private static void logServerPort(StringBuilder b, Request request, Response response)
    {
        b.append(request.getServerPort());
    }

    private static void logClientPort(StringBuilder b, Request request, Response response)
    {
        b.append(request.getRemotePort());
    }

    private static void logLocalPort(StringBuilder b, Request request, Response response)
    {
        b.append(request.getHttpChannel().getEndPoint().getLocalAddress().getPort());
    }

    private static void logRemotePort(StringBuilder b, Request request, Response response)
    {
        b.append(request.getHttpChannel().getEndPoint().getRemoteAddress().getPort());
    }

    private static void logResponseSize(StringBuilder b, Request request, Response response)
    {
        long written = response.getHttpChannel().getBytesWritten();
        b.append(written);
    }

    private static void logResponseSizeCLF(StringBuilder b, Request request, Response response)
    {
        long written = response.getHttpChannel().getBytesWritten();
        if (written == 0)
            b.append('-');
        else
            b.append(written);
    }

    private static void logBytesSent(StringBuilder b, Request request, Response response)
    {
        b.append(response.getHttpChannel().getBytesWritten());
    }

    private static void logBytesSentCLF(StringBuilder b, Request request, Response response)
    {
        long sent = response.getHttpChannel().getBytesWritten();
        if (sent == 0)
            b.append('-');
        else
            b.append(sent);
    }

    private static void logBytesReceived(StringBuilder b, Request request, Response response)
    {
        //todo this be content received rather than consumed
        b.append(request.getHttpInput().getContentConsumed());
    }

    private static void logBytesReceivedCLF(StringBuilder b, Request request, Response response)
    {
        //todo this be content received rather than consumed
        long received = request.getHttpInput().getContentConsumed();
        if (received == 0)
            b.append('-');
        else
            b.append(received);
    }

    private static void logBytesTransferred(StringBuilder b, Request request, Response response)
    {
        //todo this be content received rather than consumed
        b.append(request.getHttpInput().getContentConsumed() + response.getHttpOutput().getWritten());
    }

    private static void logBytesTransferredCLF(StringBuilder b, Request request, Response response)
    {
        //todo this be content received rather than consumed
        long transferred = request.getHttpInput().getContentConsumed() + response.getHttpOutput().getWritten();
        if (transferred == 0)
            b.append('-');
        else
            b.append(transferred);
    }

    private static void logRequestCookie(String arg, StringBuilder b, Request request, Response response)
    {
        for (Cookie c : request.getCookies())
        {
            if (arg.equals(c.getName()))
            {
                b.append(c.getValue());
                return;
            }
        }

        b.append('-');
    }

    private static void logRequestCookies(StringBuilder b, Request request, Response response)
    {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0)
            b.append("-");
        else
        {
            for (int i = 0; i < cookies.length; i++)
            {
                if (i != 0)
                    b.append(';');
                b.append(cookies[i].getName());
                b.append('=');
                b.append(cookies[i].getValue());
            }
        }
    }

    private static void logEnvironmentVar(String arg, StringBuilder b, Request request, Response response)
    {
        append(b, System.getenv(arg));
    }

    private static void logFilename(StringBuilder b, Request request, Response response)
    {
        UserIdentity.Scope scope = request.getUserIdentityScope();
        if (scope == null || scope.getContextHandler() == null)
            b.append('-');
        else
        {
            ContextHandler context = scope.getContextHandler();
            int lengthToStrip = scope.getContextPath().length() > 1 ? scope.getContextPath().length() : 0;
            String filename = context.getServletContext().getRealPath(request.getPathInfo().substring(lengthToStrip));
            append(b, filename);
        }
    }

    private static void logRequestProtocol(StringBuilder b, Request request, Response response)
    {
        append(b, request.getProtocol());
    }

    private static void logRequestHeader(String arg, StringBuilder b, Request request, Response response)
    {
        append(b, request.getHeader(arg));
    }

    private static void logKeepAliveRequests(StringBuilder b, Request request, Response response)
    {
        long requests = request.getHttpChannel().getConnection().getMessagesIn();
        if (requests >= 0)
            b.append(requests);
        else
            b.append('-');
    }

    private static void logRequestMethod(StringBuilder b, Request request, Response response)
    {
        append(b, request.getMethod());
    }

    private static void logResponseHeader(String arg, StringBuilder b, Request request, Response response)
    {
        append(b, response.getHeader(arg));
    }

    private static void logQueryString(StringBuilder b, Request request, Response response)
    {
        append(b, "?" + request.getQueryString());
    }

    private static void logRequestFirstLine(StringBuilder b, Request request, Response response)
    {
        append(b, request.getMethod());
        b.append(" ");
        append(b, request.getOriginalURI());
        b.append(" ");
        append(b, request.getProtocol());
    }

    private static void logRequestHandler(StringBuilder b, Request request, Response response)
    {
        append(b, request.getServletName());
    }

    private static void logResponseStatus(StringBuilder b, Request request, Response response)
    {
        //todo can getCommittedMetaData be null? check what happens when its aborted
        b.append(response.getCommittedMetaData().getStatus());
    }

    private static void logRequestTime(DateCache dateCache, StringBuilder b, Request request, Response response)
    {
        b.append('[');
        append(b, dateCache.format(request.getTimeStamp()));
        b.append(']');
    }

    private static void logLatencyMicroseconds(StringBuilder b, Request request, Response response)
    {
        long currentTime = System.currentTimeMillis();
        long requestTime = request.getTimeStamp();

        long latencyMs = currentTime - requestTime;
        long latencyUs = TimeUnit.MILLISECONDS.toMicros(latencyMs);

        b.append(latencyUs);
    }

    private static void logLatencyMilliseconds(StringBuilder b, Request request, Response response)
    {
        long latency = System.currentTimeMillis() - request.getTimeStamp();
        b.append(latency);
    }

    private static void logLatencySeconds(StringBuilder b, Request request, Response response)
    {
        long latency = System.currentTimeMillis() - request.getTimeStamp();
        b.append(TimeUnit.MILLISECONDS.toSeconds(latency));
    }

    private static void logRequestAuthentication(StringBuilder b, Request request, Response response)
    {
        append(b, getAuthentication(request, false));
    }

    private static void logRequestAuthenticationWithDeferred(StringBuilder b, Request request, Response response)
    {
        append(b, getAuthentication(request, true));
    }

    private static void logUrlRequestPath(StringBuilder b, Request request, Response response)
    {
        append(b, request.getRequestURI());
    }

    private static void logConnectionStatus(StringBuilder b, Request request, Response response)
    {
        b.append(request.getHttpChannel().isResponseCompleted() ? (request.getHttpChannel().isPersistent() ? '+' : '-') : 'X');
    }

    private static void logRequestTrailer(String arg, StringBuilder b, Request request, Response response)
    {
        HttpFields trailers = request.getTrailers();
        if (trailers != null)
            append(b, trailers.get(arg));
        else
            b.append('-');
    }

    private static void logResponseTrailer(String arg, StringBuilder b, Request request, Response response)
    {
        Supplier<HttpFields> supplier = response.getTrailers();
        if (supplier != null)
        {
            HttpFields trailers = supplier.get();

            if (trailers != null)
                append(b, trailers.get(arg));
            else
                b.append('-');
        }
        else
            b.append("-");
    }
}