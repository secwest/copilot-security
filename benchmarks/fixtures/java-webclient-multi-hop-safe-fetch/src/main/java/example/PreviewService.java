package example;

import reactor.core.publisher.Mono;

public final class PreviewService {
    private final PreviewTransport transport;

    public PreviewService(PreviewTransport transport) {
        this.transport = transport;
    }

    public Mono<Integer> fetch(String destination) {
        return transport.fetch(destination);
    }
}
