package example;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.Result;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

final class R2dbcSpiStatementSqlInjectionWitnessTest {
  private Connection connection;

  @BeforeEach
  void createDatabase() {
    connection =
        Mono.from(
                ConnectionFactories.get(
                        "r2dbc:h2:mem:///spi_accounts;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE")
                    .create())
            .block();
    executeFixed("DROP TABLE IF EXISTS accounts");
    executeFixed("CREATE TABLE accounts (username VARCHAR(80), role VARCHAR(80))");
    executeFixed("INSERT INTO accounts (username, role) VALUES ('victim', 'user')");
    executeFixed(
        "INSERT INTO accounts (username, role) VALUES ('administrator', 'admin')");
  }

  @AfterEach
  void closeConnection() {
    Mono.from(connection.close()).block();
  }

  @Test
  void requestValueChangesStatementPredicateAndReadsAdministratorRow() {
    var controller = new AccountController(new AccountQueries(connection));
    Map<String, String> result =
        Flux.from(controller.lookup("nobody' OR role = 'admin' -- "))
            .flatMap(
                item ->
                    item.map(
                        (row, metadata) ->
                            Map.of(
                                "username", row.get("USERNAME", String.class),
                                "role", row.get("ROLE", String.class))))
            .blockFirst();

    assertEquals("administrator", result.get("username"));
    assertEquals("admin", result.get("role"));
  }

  private void executeFixed(String sql) {
    Flux.from(connection.createStatement(sql).execute())
        .flatMap(Result::getRowsUpdated)
        .then()
        .block();
  }
}
