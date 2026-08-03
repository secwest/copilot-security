package example;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import org.springframework.stereotype.Repository;

@Repository
public final class PreviewTransport {
    private static final Map<String, URI> ALLOWED_DESTINATIONS = Map.of(
            "status", URI.create("https://status.example.invalid/health"));

    private final HttpClient client;

    public PreviewTransport(HttpClient client) {
        this.client = client;
    }

    public String fetch(String destinationKey) throws Exception {
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalStateException("Preview client must reject redirects");
        }
        URI destination = ALLOWED_DESTINATIONS.get(destinationKey);
        if (destination == null) {
            throw new SecurityException("Unknown preview destination");
        }
        HttpRequest request = HttpRequest.newBuilder(destination).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
