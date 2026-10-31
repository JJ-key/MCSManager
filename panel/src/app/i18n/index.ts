// I18n init configuration (Web Panel)
// If you want to add the language of your own country, you need to add the code here.

import i18next from "i18next";

import en_us from "@languages/en_US.json";

i18next.init({
  interpolation: {
    escapeValue: false
  },
  lng: "en_us",
  fallbackLng: "en_us",
  resources: {
    en_us: {
      translation: en_us
    },
  }
});

// alias
const $t = i18next.t;

export { $t, i18next };
