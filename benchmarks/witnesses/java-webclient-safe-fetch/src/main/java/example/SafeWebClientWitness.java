package example;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

public final class SafeWebClientWitness {
    private SafeWebClientWitness() {
    }

    public static void main(String[] args) throws Exception {
        AtomicInteger attackerRequests = new AtomicInteger();
        AtomicInteger fixedRequests = new AtomicInteger();
        HttpServer attackerService = server("private-metadata", attackerRequests);
        HttpServer fixedService = server("public-status", fixedRequests);

        try {
            URI attackerUri = URI.create("http://127.0.0.1:"
                    + attackerService.getAddress().getPort() + "/metadata");
            URI fixedStatus = URI.create("http://127.0.0.1:"
                    + fixedService.getAddress().getPort() + "/health");
            Map<String, URI> allowedDestinations = Map.of("status", fixedStatus);
            HttpClient transport = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
            WebClient client = WebClient.builder()
                    .clientConnector(new JdkClientHttpConnector(transport))
                    .build();

            boolean rejected = false;
            try {
                fetch(client, allowedDestinations, attackerUri.toString());
            } catch (IllegalArgumentException expected) {
                rejected = true;
            }
            String status = fetch(client, allowedDestinations, "status");

            if (!rejected || !"public-status".equals(status)
                    || attackerRequests.get() != 0 || fixedRequests.get() != 1) {
                throw new AssertionError("fixed-destination WebClient control failed");
            }
            System.out.println("Safe WebClient witness rejected a complete URI and selected one fixed destination.");
        } finally {
            attackerService.stop(0);
            fixedService.stop(0);
        }
    }

    private static String fetch(WebClient client, Map<String, URI> allowed, String key) {
        URI destination = allowed.get(key);
        if (destination == null) {
            throw new IllegalArgumentException("unknown destination");
        }
        return client.get()
                .uri(destination)
                .retrieve()
                .bodyToMono(String.class)
                .block(Duration.ofSeconds(5));
    }

    private static HttpServer server(String response, AtomicInteger requests) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            byte[] body = response.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        return server;
    }
}
