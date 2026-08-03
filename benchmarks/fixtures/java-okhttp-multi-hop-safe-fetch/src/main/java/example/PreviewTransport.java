package example;

import java.io.IOException;
import java.util.Map;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public final class PreviewTransport {
    private static final Map<String, String> ALLOWED_DESTINATIONS = Map.of(
            "status", "https://status.example.invalid/health");

    public int fetch(String destinationKey) {
        OkHttpClient client = new OkHttpClient.Builder()
                .followRedirects(false)
                .followSslRedirects(false)
                .build();
        String destination = ALLOWED_DESTINATIONS.get(destinationKey);
        if (destination == null) {
            throw new IllegalArgumentException("unknown destination");
        }
        Request request = new Request.Builder()
                .url(destination)
                .build();
        try (Response response = client.newCall(request).execute()) {
            return response.code();
        } catch (IOException error) {
            throw new IllegalStateException(error);
        }
    }
}
