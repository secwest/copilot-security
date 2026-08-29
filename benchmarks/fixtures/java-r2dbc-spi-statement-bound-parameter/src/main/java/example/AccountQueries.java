package example;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.Result;
import io.r2dbc.spi.Statement;
import org.reactivestreams.Publisher;

public final class AccountQueries {
  private final Connection connection;

  public AccountQueries(Connection connection) {
    this.connection = connection;
  }

  public Publisher<? extends Result> lookup(String username) {
    Statement statement =
        connection.createStatement(
            "SELECT username, role FROM accounts WHERE username = $1");
    statement.bind(0, username);
    return statement.execute();
  }
}
