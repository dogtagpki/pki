package com.netscape.certsrv.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.base.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

public class PKIConnectionTest {

    private HttpServer server;
    private String serverURL;

    @BeforeEach
    public void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        serverURL = "http://localhost:" + server.getAddress().getPort();
        server.start();
    }

    @AfterEach
    public void tearDown() {
        server.stop(0);
    }

    private ClientConfig config() throws Exception {
        ClientConfig config = new ClientConfig();
        config.setServerURL(serverURL);
        return config;
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (var out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Test
    public void testRedirectPreservesMethodAndBody() throws Exception {
        server.createContext("/redirect", exchange -> {
            exchange.getRequestBody().readAllBytes();
            int status = Integer.parseInt(exchange.getRequestURI().getQuery());
            exchange.getResponseHeaders().add("Location", "/target");
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        server.createContext("/target", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            respond(exchange, 200, exchange.getRequestMethod() + ":" + body);
        });

        try (PKIConnection connection = new PKIConnection(config())) {
            for (int status : List.of(301, 302, 303, 307, 308)) {
                ClassicHttpRequest request = ClassicRequestBuilder.post(serverURL + "/redirect?" + status)
                        .setEntity(new StringEntity("test=hello", ContentType.APPLICATION_FORM_URLENCODED))
                        .build();
                try (ClassicHttpResponse response = connection.getHttpClient().executeOpen(null, request, null)) {
                    assertEquals(200, response.getCode());
                    assertEquals("POST:test=hello", EntityUtils.toString(response.getEntity()), "HTTP " + status);
                }
            }
        }
    }

    @Test
    public void testRedirectPreservesPutAndPatchOnSeeOther() throws Exception {
        server.createContext("/redirect", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Location", "/target");
            exchange.sendResponseHeaders(303, -1);
            exchange.close();
        });
        server.createContext("/target", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            respond(exchange, 200, exchange.getRequestMethod() + ":" + body);
        });

        try (PKIConnection connection = new PKIConnection(config())) {
            for (String method : List.of("PUT", "PATCH", "DELETE")) {
                ClassicHttpRequest request = ClassicRequestBuilder.create(method)
                        .setUri(serverURL + "/redirect")
                        .setEntity(new StringEntity("body", ContentType.TEXT_PLAIN))
                        .build();
                try (ClassicHttpResponse response = connection.getHttpClient().executeOpen(null, request, null)) {
                    assertEquals(method + ":body", EntityUtils.toString(response.getEntity()));
                }
            }
        }
    }

    @Test
    public void testRedirectDoesNotForwardSensitiveHeaders() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        HttpServer other = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        other.createContext("/target", exchange -> {
            requests.incrementAndGet();
            respond(exchange, 200, "unexpected");
        });
        other.start();
        try {
            server.createContext("/redirect", exchange -> {
                exchange.getRequestBody().readAllBytes();
                exchange.getResponseHeaders().add("Location",
                        "http://localhost:" + other.getAddress().getPort() + "/target");
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
            });
            try (PKIConnection connection = new PKIConnection(config())) {
                for (String header : List.of("Authorization", "Cookie")) {
                    ClassicHttpRequest request = ClassicRequestBuilder.post(serverURL + "/redirect")
                            .setHeader(header, "secret")
                            .setEntity(new StringEntity("body"))
                            .build();
                    try (ClassicHttpResponse response = connection.getHttpClient().executeOpen(null, request, null)) {
                        assertEquals(302, response.getCode());
                    }
                }
                assertEquals(0, requests.get());
            }
        } finally {
            other.stop(0);
        }
    }

    @Test
    public void testBasicAuthenticationAndSessionCookie() throws Exception {
        AtomicInteger challenges = new AtomicInteger();
        server.createContext("/login", exchange -> {
            if (!"Basic dXNlcjpwYXNzd29yZA==".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                challenges.incrementAndGet();
                exchange.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"PKI\"");
                respond(exchange, 401, "Authentication required");
                return;
            }
            exchange.getResponseHeaders().add("Set-Cookie", "JSESSIONID=session; Path=/; HttpOnly");
            respond(exchange, 200, "Authenticated");
        });
        server.createContext("/session", exchange ->
                respond(exchange, 200, String.valueOf(exchange.getRequestHeaders().getFirst("Cookie"))));
        ClientConfig config = config();
        config.setUsername("user");
        config.setPassword("password");
        try (PKIClient client = new PKIClient(config)) {
            assertEquals("Authenticated", client.get("/login", String.class));
            assertEquals("JSESSIONID=session", client.get("/session", String.class));
            assertEquals(1, challenges.get());
        }
    }

    @Test
    public void testRedirectUsesUpdatedSessionCookie() throws Exception {
        server.createContext("/login", exchange -> {
            exchange.getResponseHeaders().add("Set-Cookie", "JSESSIONID=old; Path=/");
            respond(exchange, 200, "Authenticated");
        });
        server.createContext("/redirect", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Set-Cookie", "JSESSIONID=new; Path=/");
            exchange.getResponseHeaders().add("Location", "/session");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/session", exchange ->
                respond(exchange, 200, String.valueOf(exchange.getRequestHeaders().getFirst("Cookie"))));

        try (PKIClient client = new PKIClient(config())) {
            assertEquals("Authenticated", client.get("/login", String.class));
            assertEquals("JSESSIONID=new", client.post("/redirect", String.class));
        }
    }

    @Test
    public void testRedirectAcrossOriginsPreservesBody() throws Exception {
        HttpServer other = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        other.createContext("/target", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            respond(exchange, 200, exchange.getRequestMethod() + ":" + body);
        });
        other.start();
        try {
            server.createContext("/redirect", exchange -> {
                exchange.getRequestBody().readAllBytes();
                exchange.getResponseHeaders().add("Location",
                        "http://localhost:" + other.getAddress().getPort() + "/target");
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
            });
            try (PKIConnection connection = new PKIConnection(config())) {
                ClassicHttpRequest request = ClassicRequestBuilder.post(serverURL + "/redirect")
                        .setEntity(new StringEntity("body"))
                        .build();
                try (ClassicHttpResponse response = connection.getHttpClient().executeOpen(null, request, null)) {
                    assertEquals("POST:body", EntityUtils.toString(response.getEntity()));
                }
            }
        } finally {
            other.stop(0);
        }
    }

    @Test
    public void testConnectionCanBeReusedAfterErrorResponse() throws Exception {
        server.createContext("/error", exchange -> respond(exchange, 401, "Authentication required"));
        server.createContext("/success", exchange -> respond(exchange, 200, "success"));
        try (PKIClient client = new PKIClient(config())) {
            for (int i = 0; i < 10; i++) {
                assertThrows(UnauthorizedException.class, () -> client.get("/error", String.class));
                assertEquals("success", client.get("/success", String.class));
            }
        }
    }

    @Test
    public void testFailedRequestIsNotRetried() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        server.createContext("/disconnect", exchange -> {
            requests.incrementAndGet();
            exchange.close();
        });
        try (PKIConnection connection = new PKIConnection(config())) {
            assertThrows(IOException.class, () -> connection.getHttpClient()
                    .executeOpen(null, new HttpGet(serverURL + "/disconnect"), null));
            assertEquals(1, requests.get());
        }
    }

    @Test
    public void testClientCloseClosesConnectionManager() throws Exception {
        PKIConnection connection = new PKIConnection(config());
        connection.close();
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> connection.getHttpClient().executeOpen(null, new HttpGet(serverURL), null));
        assertTrue(exception.getMessage().contains("Connection pool shut down"));
    }
}
