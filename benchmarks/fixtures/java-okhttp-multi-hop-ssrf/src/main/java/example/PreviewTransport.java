package example;

import java.io.IOException;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public final class PreviewTransport {
    private final OkHttpClient client;

    public PreviewTransport(OkHttpClient client) {
        this.client = client;
    }

    public int fetch(String target) {
        Request request = new Request.Builder()
                .url(target)
                .build();
        try (Response response = client.newCall(request).execute()) {
            return response.code();
        } catch (IOException error) {
            throw new IllegalStateException(error);
        }
    }
}
