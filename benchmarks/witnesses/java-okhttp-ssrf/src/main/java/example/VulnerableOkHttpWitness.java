package example;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public final class VulnerableOkHttpWitness {
    private VulnerableOkHttpWitness() {
    }

    public static void main(String[] args) throws Exception {
        AtomicInteger privateRequests = new AtomicInteger();
        HttpServer privateService = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        privateService.createContext("/metadata", exchange -> {
            privateRequests.incrementAndGet();
            byte[] body = "private-metadata".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        privateService.start();

        try {
            String attackerControlled = "http://127.0.0.1:"
                    + privateService.getAddress().getPort() + "/metadata";
            OkHttpClient client = new OkHttpClient.Builder()
                    .followRedirects(true)
                    .followSslRedirects(true)
                    .build();
            try {
                Request request = new Request.Builder()
                        .url(attackerControlled)
                        .build();

                try (Response response = client.newCall(request).execute()) {
                    String leaked = response.body().string();
                    if (!"private-metadata".equals(leaked) || privateRequests.get() != 1) {
                        throw new AssertionError("attacker URL did not reach the private service");
                    }
                }
            } finally {
                shutdown(client);
            }
            System.out.println("Vulnerable OkHttp witness reached a private loopback service.");
        } finally {
            privateService.stop(0);
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
