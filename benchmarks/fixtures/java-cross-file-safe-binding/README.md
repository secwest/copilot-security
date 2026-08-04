# Spring MVC explicit-binding control fixture

The controller retains the same bound JPA entity, service, and repository topology, but an attribute-scoped `@InitBinder` permits only `displayName`. The sensitive `administrator` property is not eligible for property binding.

`AccountBindingWitnessTest` submits the same real form request through Spring MockMvc and proves that the display name is persisted while the attempted privilege field remains false.
