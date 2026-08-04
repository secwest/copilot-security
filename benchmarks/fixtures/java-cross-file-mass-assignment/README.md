# Spring MVC mass-assignment exploit fixture

The controller binds form fields directly onto a JPA `Account` entity and passes that same entity through a typed service to `JpaRepository.save`. The entity exposes an `administrator` setter that the endpoint never intended callers to control.

`AccountBindingWitnessTest` submits a real form request through Spring MockMvc and proves that `administrator=true` is persisted by Hibernate into H2.
