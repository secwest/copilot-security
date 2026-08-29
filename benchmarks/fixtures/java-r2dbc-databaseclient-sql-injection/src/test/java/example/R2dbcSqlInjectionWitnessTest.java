package example;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.r2dbc.spi.ConnectionFactories;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.r2dbc.core.DatabaseClient;

final class R2dbcSqlInjectionWitnessTest {
  private DatabaseClient client;

  @BeforeEach
  void createDatabase() {
    client =
        DatabaseClient.create(
            ConnectionFactories.get(
                "r2dbc:h2:mem:///accounts;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"));
    client.sql("DROP TABLE IF EXISTS accounts").then().block();
    client
        .sql("CREATE TABLE accounts (username VARCHAR(80), role VARCHAR(80))")
        .then()
        .block();
    client
        .sql("INSERT INTO accounts (username, role) VALUES ('victim', 'user')")
        .then()
        .block();
    client
        .sql("INSERT INTO accounts (username, role) VALUES ('administrator', 'admin')")
        .then()
        .block();
  }

  @Test
  void requestValueChangesPredicateAndReadsAdministratorRow() {
    var controller = new AccountController(new AccountQueries(client));
    Map<String, Object> row = controller.lookup("nobody' OR role = 'admin' -- ").block();

    assertEquals("administrator", row.get("USERNAME"));
    assertEquals("admin", row.get("ROLE"));
  }
}
