package example;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public final class SafeOkHttpWitness {
    private SafeOkHttpWitness() {
    }

    public static void main(String[] args) throws Exception {
        AtomicInteger statusRequests = new AtomicInteger();
        HttpServer statusService = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        statusService.createContext("/health", exchange -> {
            statusRequests.incrementAndGet();
            byte[] body = "healthy".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        statusService.start();

        try {
            String fixedStatus = "http://127.0.0.1:"
                    + statusService.getAddress().getPort() + "/health";
            Map<String, String> allowedDestinations = Map.of("status", fixedStatus);
            OkHttpClient client = new OkHttpClient.Builder()
                    .followRedirects(false)
                    .followSslRedirects(false)
                    .build();
            try {
                String attackerUrl = "http://127.0.0.1:1/metadata";

                if (fetch(client, allowedDestinations, attackerUrl) != null) {
                    throw new AssertionError("complete attacker URL was accepted as a key");
                }
                String body = fetch(client, allowedDestinations, "status");
                if (!"healthy".equals(body) || statusRequests.get() != 1) {
                    throw new AssertionError("fixed destination control failed");
                }
            } finally {
                shutdown(client);
            }
            System.out.println("Safe OkHttp witness rejected a complete URL and selected one fixed destination.");
        } finally {
            statusService.stop(0);
        }
    }

    private static String fetch(
            OkHttpClient client,
            Map<String, String> allowedDestinations,
            String key) throws Exception {
        String destination = allowedDestinations.get(key);
        if (destination == null) {
            return null;
        }
        Request request = new Request.Builder()
                .url(destination)
                .build();
        try (Response response = client.newCall(request).execute()) {
            return response.body().string();
        }
    }

    private static void shutdown(OkHttpClient client) throws Exception {
        client.dispatcher().executorService().shutdown();
        client.connectionPool().evictAll();
        if (client.cache() != null) {
            client.cache().close();
        }
    }
}
