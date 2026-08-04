package example;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "spring.jpa.open-in-view=false")
@AutoConfigureMockMvc
class AccountBindingWitnessTest {
  @Autowired private MockMvc mvc;
  @Autowired private AccountRepository repository;

  @BeforeEach
  void resetRepository() {
    repository.deleteAll();
  }

  @Test
  void allowlistRejectsTheAdministrativeField() throws Exception {
    mvc.perform(
            post("/accounts")
                .param("displayName", "Member")
                .param("administrator", "true"))
        .andExpect(status().isOk());

    Account persisted = repository.findAll().getFirst();
    assertThat(persisted.getDisplayName()).isEqualTo("Member");
    assertThat(persisted.isAdministrator()).isFalse();
  }
}
