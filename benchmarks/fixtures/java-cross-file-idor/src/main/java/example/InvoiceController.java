package example;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InvoiceController {
  private final InvoiceService invoices;

  public InvoiceController(InvoiceService invoices) {
    this.invoices = invoices;
  }

  @PreAuthorize("isAuthenticated()")
  @GetMapping("/invoices/{invoiceId}")
  public Invoice getInvoice(
      @PathVariable long invoiceId, Authentication authentication) {
    return invoices.loadInvoice(invoiceId);
  }
}
