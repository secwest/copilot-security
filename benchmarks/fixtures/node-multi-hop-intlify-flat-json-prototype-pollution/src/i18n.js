import { createI18n } from "vue-i18n";

export function configureI18n(messages) {
  return createI18n({
    legacy: false,
    flatJson: true,
    messages: { en: messages },
  });
}
