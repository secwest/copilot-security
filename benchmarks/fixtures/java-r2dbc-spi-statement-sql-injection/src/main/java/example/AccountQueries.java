package example;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.Result;
import org.reactivestreams.Publisher;

public final class AccountQueries {
  private final Connection connection;

  public AccountQueries(Connection connection) {
    this.connection = connection;
  }

  public Publisher<? extends Result> lookup(String username) {
    String sql =
        "SELECT username, role FROM accounts WHERE username = '" + username + "'";
    return connection.createStatement(sql).execute();
  }
}
