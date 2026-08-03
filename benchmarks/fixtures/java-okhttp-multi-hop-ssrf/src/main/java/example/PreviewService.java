package example;

public final class PreviewService {
    private final PreviewTransport transport;

    public PreviewService(PreviewTransport transport) {
        this.transport = transport;
    }

    public int fetch(String target) {
        return transport.fetch(target);
    }
}
