package example;

import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {
  private final AccountService accounts;

  public AccountController(AccountService accounts) {
    this.accounts = accounts;
  }

  @PostMapping("/accounts")
  public Account create(@ModelAttribute Account account) {
    return accounts.create(account);
  }
}
