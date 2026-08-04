package example;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
    repository.save(new Invoice(1L, "customer-100", "attacker invoice"));
    repository.save(new Invoice(2L, "customer-200", "victim invoice"));
    SecurityContextHolder.getContext()
        .setAuthentication(new TestingAuthenticationToken("customer-100", "n/a", "ROLE_USER"));
  }

  @AfterEach
  void clearAuthentication() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void attackerSelectedKeyReturnsVictimInvoice() {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    var selected = controller.getInvoice(2L, authentication);
    assertEquals("customer-200", selected.getCustomerId());
    assertEquals("victim invoice", selected.getDescription());
  }
}
