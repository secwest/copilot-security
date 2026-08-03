import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

public final class VulnerableSsrfWitness {
    private static String fetch(String requested) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
        HttpRequest request = HttpRequest.newBuilder(URI.create(requested)).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    public static void main(String[] args) throws Exception {
        AtomicInteger requests = new AtomicInteger();
        HttpServer metadata = HttpServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        metadata.createContext("/metadata", exchange -> {
            requests.incrementAndGet();
            byte[] body = "private-metadata".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (var response = exchange.getResponseBody()) {
                response.write(body);
            }
        });
        metadata.start();
        try {
            String attackerTarget = "http://127.0.0.1:"
                    + metadata.getAddress().getPort() + "/metadata";
            if (!fetch(attackerTarget).equals("private-metadata") || requests.get() != 1) {
                throw new AssertionError("Attacker-controlled URI did not reach the private service");
            }
            System.out.println("Vulnerable Java SSRF witness reached a private loopback service.");
        } finally {
            metadata.stop(0);
        }
    }
}
