package example;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class InvoiceService {
  private final InvoiceRepository repository;

  public InvoiceService(InvoiceRepository repository) {
    this.repository = repository;
  }

  public Invoice loadInvoice(long invoiceId, Authentication authentication) {
    return repository
        .findByIdAndCustomerId(invoiceId, authentication.getName())
        .orElseThrow();
  }
}
