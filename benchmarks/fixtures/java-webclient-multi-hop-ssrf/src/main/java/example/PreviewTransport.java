package example;

import java.time.Duration;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

public final class PreviewTransport {
    private final WebClient client;

    public PreviewTransport(WebClient client) {
        this.client = client;
    }

    public Mono<Integer> fetch(String target) {
        return client.get()
                .uri(target)
                .exchangeToMono(response -> response.releaseBody()
                        .thenReturn(response.statusCode().value()))
                .timeout(Duration.ofSeconds(2));
    }
}
