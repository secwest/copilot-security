package example;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

public final class VulnerableWebClientWitness {
    private VulnerableWebClientWitness() {
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
            URI attackerControlled = URI.create("http://127.0.0.1:"
                    + privateService.getAddress().getPort() + "/metadata");
            HttpClient transport = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.ALWAYS)
                    .build();
            WebClient client = WebClient.builder()
                    .clientConnector(new JdkClientHttpConnector(transport))
                    .build();

            String leaked = client.get()
                    .uri(attackerControlled)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block(Duration.ofSeconds(5));

            if (!"private-metadata".equals(leaked) || privateRequests.get() != 1) {
                throw new AssertionError("attacker URI did not reach the private service");
            }
            System.out.println("Vulnerable WebClient witness reached a private loopback service.");
        } finally {
            privateService.stop(0);
        }
    }
}
