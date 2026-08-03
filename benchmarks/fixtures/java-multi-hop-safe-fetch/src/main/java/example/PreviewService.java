package example;

import org.springframework.stereotype.Service;

@Service
public final class PreviewService {
    private final PreviewTransport transport;

    public PreviewService(PreviewTransport transport) {
        this.transport = transport;
    }

    public String fetch(String destinationKey) throws Exception {
        return transport.fetch(destinationKey);
    }
}
