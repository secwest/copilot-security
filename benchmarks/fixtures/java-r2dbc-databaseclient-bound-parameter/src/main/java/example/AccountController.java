package example;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import reactor.core.publisher.Mono;

public final class AccountController {
  private final AccountQueries queries;

  public AccountController(AccountQueries queries) {
    this.queries = queries;
  }

  @GetMapping("/accounts/lookup")
  public Mono<Map<String, Object>> lookup(@RequestParam String username) {
    return queries.lookup(username);
  }
}
