package example;

import org.springframework.stereotype.Service;

@Service
public class InvoiceService {
  private final InvoiceRepository repository;

  public InvoiceService(InvoiceRepository repository) {
    this.repository = repository;
  }

  public Invoice loadInvoice(long invoiceId) {
    return repository.findById(invoiceId).orElseThrow();
  }
}
