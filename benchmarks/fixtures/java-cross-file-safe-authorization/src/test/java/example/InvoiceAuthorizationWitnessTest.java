package example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.NoSuchElementException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

@SpringBootTest
class InvoiceAuthorizationWitnessTest {
  @Autowired private InvoiceController controller;
  @Autowired private InvoiceRepository repository;

  @BeforeEach
  void seedInvoices() {
    repository.deleteAll();
    repository.save(new Invoice(1L, "customer-100", "caller invoice"));
    repository.save(new Invoice(2L, "customer-200", "other invoice"));
    SecurityContextHolder.getContext()
        .setAuthentication(new TestingAuthenticationToken("customer-100", "n/a", "ROLE_USER"));
  }

  @AfterEach
  void clearAuthentication() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void principalBoundQueryRejectsCrossCustomerSelection() {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    assertThrows(
        NoSuchElementException.class,
        () -> controller.getInvoice(2L, authentication));
    assertEquals(
        "caller invoice",
        controller.getInvoice(1L, authentication).getDescription());
  }
}
