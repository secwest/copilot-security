package example;

import org.springframework.stereotype.Service;

@Service
public class AccountService {
  private final AccountRepository repository;

  public AccountService(AccountRepository repository) {
    this.repository = repository;
  }

  public Account create(Account account) {
    return repository.save(account);
  }
}
