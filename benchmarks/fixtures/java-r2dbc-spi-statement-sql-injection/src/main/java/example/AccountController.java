package example;

import io.r2dbc.spi.Result;
import org.reactivestreams.Publisher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public final class AccountController {
  private final AccountQueries queries;

  public AccountController(AccountQueries queries) {
    this.queries = queries;
  }

  @GetMapping("/accounts/lookup")
  public Publisher<? extends Result> lookup(@RequestParam String username) {
    return queries.lookup(username);
  }
}
