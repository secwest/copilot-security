package example;

import java.util.Map;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

public final class AccountQueries {
  private final DatabaseClient client;

  public AccountQueries(DatabaseClient client) {
    this.client = client;
  }

  public Mono<Map<String, Object>> lookup(String username) {
    String sql =
        "SELECT username, role FROM accounts WHERE username = '" + username + "'";
    return client.sql(sql).fetch().one();
  }
}
