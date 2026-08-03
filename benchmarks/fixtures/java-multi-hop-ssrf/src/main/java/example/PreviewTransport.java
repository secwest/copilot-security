package example;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.springframework.stereotype.Repository;

@Repository
public final class PreviewTransport {
    private final HttpClient client;

    public PreviewTransport(HttpClient client) {
        this.client = client;
    }

    public String fetch(String target) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(target))
                .timeout(java.time.Duration.ofSeconds(2))
                .GET()
                .build();
        HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
        return Integer.toString(response.statusCode());
    }
}
