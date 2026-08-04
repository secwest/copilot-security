package example;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
public class Invoice {
  @Id private Long id;
  private String customerId;
  private String description;

  protected Invoice() {}

  public Invoice(Long id, String customerId, String description) {
    this.id = id;
    this.customerId = customerId;
    this.description = description;
  }

  public Long getId() {
    return id;
  }

  public String getCustomerId() {
    return customerId;
  }

  public String getDescription() {
    return description;
  }
}
