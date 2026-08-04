package example;

import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {
  private final AccountService accounts;

  public AccountController(AccountService accounts) {
    this.accounts = accounts;
  }

  @InitBinder("account")
  void configureAccountBinding(WebDataBinder binder) {
    binder.setAllowedFields("displayName");
  }

  @PostMapping("/accounts")
  public Account create(@ModelAttribute Account account) {
    return accounts.create(account);
  }
}
