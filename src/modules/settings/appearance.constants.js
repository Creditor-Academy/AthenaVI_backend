const DEFAULT_APPEARANCE = {
  interfaceMode: 'light',
  themePalette: 'sapphire',
  customAccentColor: '#2563EB',
};

const INTERFACE_MODE_TO_DB = {
  light: 'LIGHT',
  dark: 'DARK',
};

const INTERFACE_MODE_FROM_DB = {
  LIGHT: 'light',
  DARK: 'dark',
};

const THEME_PALETTE_TO_DB = {
  original: 'ORIGINAL',
  sapphire: 'SAPPHIRE',
  ocean: 'OCEAN',
  forest: 'FOREST',
  sunset: 'SUNSET',
  custom: 'CUSTOM',
};

const THEME_PALETTE_FROM_DB = {
  ORIGINAL: 'original',
  SAPPHIRE: 'sapphire',
  OCEAN: 'ocean',
  FOREST: 'forest',
  SUNSET: 'sunset',
  CUSTOM: 'custom',
};

module.exports = {
  DEFAULT_APPEARANCE,
  INTERFACE_MODE_TO_DB,
  INTERFACE_MODE_FROM_DB,
  THEME_PALETTE_TO_DB,
  THEME_PALETTE_FROM_DB,
};
