function designTokensForVisualRole({ visualRole = 'text', appearance = 'light' } = {}) {
  const isDark = appearance === 'dark';

  if (visualRole === 'cover') {
    return {
      backgroundStyle: 'image',
      overlayOpacity: isDark ? 0.45 : 0.4,
      textContrast: 'high',
    };
  }

  if (visualRole === 'closing') {
    return {
      // Prefer solid stage fill in dark mode so closing never renders as an empty black field
      backgroundStyle: 'solid',
      overlayOpacity: isDark ? 0.35 : 0.2,
      textContrast: 'normal',
    };
  }

  if (visualRole === 'visual') {
    return {
      // Light decks must not fall back to dark gradient chrome.
      backgroundStyle: isDark ? 'gradient' : 'solid',
      overlayOpacity: isDark ? 0.25 : 0.15,
      textContrast: 'normal',
    };
  }

  if (visualRole === 'balanced') {
    return {
      backgroundStyle: 'solid',
      overlayOpacity: 0.2,
      textContrast: 'normal',
    };
  }

  // text
  return {
    backgroundStyle: 'solid',
    overlayOpacity: 0.2,
    textContrast: 'normal',
  };
}

module.exports = {
  designTokensForVisualRole,
};
