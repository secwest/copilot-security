import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public final class SafeFetchWitness {
    private static String fetch(
            HttpClient client,
            Map<String, URI> allowedDestinations,
            String destinationKey
    ) throws Exception {
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalStateException("redirects");
        }
        URI destination = allowedDestinations.get(destinationKey);
        if (destination == null) {
            throw new SecurityException("unknown destination");
        }
        HttpRequest request = HttpRequest.newBuilder(destination).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    public static void main(String[] args) throws Exception {
        AtomicInteger requests = new AtomicInteger();
        HttpServer status = HttpServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        status.createContext("/health", exchange -> {
            requests.incrementAndGet();
            byte[] body = "healthy".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (var response = exchange.getResponseBody()) {
                response.write(body);
            }
        });
        status.start();
        try {
            URI fixedStatus = URI.create("http://127.0.0.1:"
                    + status.getAddress().getPort() + "/health");
            Map<String, URI> allowedDestinations = Map.of("status", fixedStatus);
            HttpClient client = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
            try {
                fetch(client, allowedDestinations, fixedStatus.toString());
                throw new AssertionError("A caller-controlled complete URI was accepted as a key");
            } catch (SecurityException expected) {
                // The rejected URI must not reach transport.
            }
            if (requests.get() != 0) {
                throw new AssertionError("Rejected URI reached the server");
            }
            if (!fetch(client, allowedDestinations, "status").equals("healthy")
                    || requests.get() != 1) {
                throw new AssertionError("Fixed destination selection did not work");
            }
            System.out.println("Safe Java fetch witness rejected a complete URI and allowed one fixed key.");
        } finally {
            status.stop(0);
        }
    }
}
