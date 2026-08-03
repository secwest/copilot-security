package example;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

public final class PreviewTransport {
    private static final Map<String, URI> ALLOWED_DESTINATIONS = Map.of(
            "status", URI.create("https://status.example.invalid/health"));

    private final HttpClient.Redirect redirectPolicy;
    private final WebClient client;

    public PreviewTransport() {
        this.redirectPolicy = HttpClient.Redirect.NEVER;
        HttpClient transport = HttpClient.newBuilder()
                .followRedirects(redirectPolicy)
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        this.client = WebClient.builder()
                .clientConnector(new JdkClientHttpConnector(transport))
                .build();
    }

    public Mono<Integer> fetch(String destinationKey) {
        if (redirectPolicy != HttpClient.Redirect.NEVER) {
            return Mono.error(new IllegalStateException("redirects must remain disabled"));
        }
        URI destination = ALLOWED_DESTINATIONS.get(destinationKey);
        if (destination == null) {
            return Mono.error(new IllegalArgumentException("unknown destination"));
        }
        return client.get()
                .uri(destination)
                .exchangeToMono(response -> response.releaseBody()
                        .thenReturn(response.statusCode().value()))
                .timeout(Duration.ofSeconds(2));
    }
}
