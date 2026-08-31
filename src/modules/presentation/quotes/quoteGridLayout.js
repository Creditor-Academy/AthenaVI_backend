const QUOTE_GRID_N = 3;
const QUOTE_MARK_COLOR = '#1E3A5F';
const QUOTE_CARD_BORDER = '#E5E7EB';

function quoteMarkInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 72 56" width="100%" height="100%"><path fill="currentColor" d="M28 8C14 14 4 28 4 42c0 8.8 6.2 16 14 16s14-7.2 14-16c0-10.4-6.2-16.8-16.5-18.4C18.8 16.8 24.2 12 28 8zm40 0C54 14 44 28 44 42c0 8.8 6.2 16 14 16s14-7.2 14-16c0-10.4-6.2-16.8-16.5-18.4C58.8 16.8 64.2 12 68 8z"/></svg>`;
}

function quoteGridFrame(canvasW, canvasH, n = QUOTE_GRID_N) {
  const insetX = 56;
  const insetY = 44;
  const headingH = 72;
  const gap = 28;
  const cardTop = insetY + headingH + 24;
  const cardH = Math.max(520, canvasH - cardTop - 48);
  const usable = canvasW - insetX * 2;
  const cardW = (usable - gap * (n - 1)) / n;
  return { canvasW, canvasH, n, insetX, insetY, headingH, gap, cardTop, cardH, cardW };
}

function quoteGridCardGeom(i, frame) {
  const { insetX, gap, cardTop, cardH, cardW } = frame;
  const x = insetX + i * (cardW + gap);
  const padX = 36;
  const padY = 32;
  const markW = 48;
  const markH = 36;
  const avatar = 56;
  const nameH = 28;
  const roleH = 22;
  const attrY = cardTop + cardH - padY - avatar;
  const quoteY = cardTop + padY + markH + 16;
  const quoteH = Math.max(120, attrY - quoteY - 24);
  const textW = Math.round(cardW - padX * 2);
  const nameX = Math.round(x + padX + avatar + 14);
  const nameW = Math.max(80, textW - avatar - 14);
  return {
    card: {
      x: Math.round(x),
      y: Math.round(cardTop),
      width: Math.round(cardW),
      height: Math.round(cardH),
    },
    mark: {
      x: Math.round(x + padX),
      y: Math.round(cardTop + padY),
      width: markW,
      height: markH,
    },
    quote: {
      x: Math.round(x + padX),
      y: Math.round(quoteY),
      width: textW,
      height: Math.round(quoteH),
    },
    avatar: {
      x: Math.round(x + padX),
      y: Math.round(attrY),
      width: avatar,
      height: avatar,
    },
    name: {
      x: nameX,
      y: Math.round(attrY + 4),
      width: nameW,
      height: nameH,
    },
    role: {
      x: nameX,
      y: Math.round(attrY + 4 + nameH),
      width: nameW,
      height: roleH,
    },
  };
}

function quotePortraitGeom(canvasW, canvasH) {
  const insetX = 96;
  const insetY = 88;
  const cardW = canvasW - insetX * 2;
  const cardH = canvasH - insetY * 2;
  const x = insetX;
  const y = insetY;
  const padX = 72;
  const padY = 56;
  const padBottom = 80;
  const markW = 56;
  const markH = 42;
  const avatar = 72;
  const nameH = 32;
  const roleH = 26;
  const attrY = y + cardH - padBottom - avatar;
  const quoteY = y + padY + markH + 28;
  const quoteH = Math.max(180, attrY - quoteY - 40);
  const quoteW = Math.round(Math.min(cardW - padX * 2, cardW * 0.72));
  const nameX = Math.round(x + padX + avatar + 18);
  const nameW = Math.round(cardW - padX * 2 - avatar - 18);
  return {
    card: { x, y, width: Math.round(cardW), height: Math.round(cardH) },
    mark: { x: Math.round(x + padX), y: Math.round(y + padY), width: markW, height: markH },
    quote: {
      x: Math.round(x + padX),
      y: Math.round(quoteY),
      width: quoteW,
      height: Math.round(quoteH),
    },
    avatar: {
      x: Math.round(x + padX),
      y: Math.round(attrY),
      width: avatar,
      height: avatar,
    },
    name: { x: nameX, y: Math.round(attrY + 6), width: nameW, height: nameH },
    role: { x: nameX, y: Math.round(attrY + 6 + nameH), width: nameW, height: roleH },
  };
}

function quoteStatementLeftGeom(canvasW, canvasH) {
  const insetX = 96;
  const insetY = 88;
  const cardW = canvasW - insetX * 2;
  const cardH = canvasH - insetY * 2;
  const x = insetX;
  const y = insetY;
  const padX = 72;
  const padY = 56;
  const padBottom = 80;
  const markW = 52;
  const markH = 40;
  const avatar = 64;
  const nameH = 30;
  const roleH = 24;
  const attrY = y + cardH - padBottom - avatar;
  const quoteY = y + padY + markH + 28;
  const quoteH = Math.max(180, attrY - quoteY - 40);
  const quoteW = Math.round(cardW * 0.48);
  const nameX = Math.round(x + padX + avatar + 16);
  const nameW = Math.max(80, quoteW - avatar - 16);
  return {
    card: { x, y, width: Math.round(cardW), height: Math.round(cardH) },
    mark: { x: Math.round(x + padX), y: Math.round(y + padY), width: markW, height: markH },
    quote: {
      x: Math.round(x + padX),
      y: Math.round(quoteY),
      width: quoteW,
      height: Math.round(quoteH),
    },
    avatar: {
      x: Math.round(x + padX),
      y: Math.round(attrY),
      width: avatar,
      height: avatar,
    },
    name: { x: nameX, y: Math.round(attrY + 4), width: nameW, height: nameH },
    role: { x: nameX, y: Math.round(attrY + 4 + nameH), width: nameW, height: roleH },
  };
}

function quoteTestimonialGeom(canvasW, canvasH) {
  const cardW = Math.min(1280, canvasW - 320);
  const cardH = Math.min(620, canvasH - 260);
  const x = Math.round((canvasW - cardW) / 2);
  const y = Math.round((canvasH - cardH) / 2);
  const padX = 64;
  const padY = 48;
  const markW = 52;
  const markH = 40;
  const avatar = 64;
  const nameH = 30;
  const roleH = 24;
  const attrY = y + cardH - padY - avatar;
  const quoteY = y + padY + markH + 24;
  const quoteH = Math.max(140, attrY - quoteY - 32);
  const quoteW = Math.round(Math.min(cardW - padX * 2, cardW * 0.78));
  const nameX = Math.round(x + padX + avatar + 16);
  const nameW = Math.round(cardW - padX * 2 - avatar - 16);
  return {
    card: { x, y, width: Math.round(cardW), height: Math.round(cardH) },
    mark: { x: Math.round(x + padX), y: Math.round(y + padY), width: markW, height: markH },
    quote: {
      x: Math.round(x + padX),
      y: Math.round(quoteY),
      width: quoteW,
      height: Math.round(quoteH),
    },
    avatar: {
      x: Math.round(x + padX),
      y: Math.round(attrY),
      width: avatar,
      height: avatar,
    },
    name: { x: nameX, y: Math.round(attrY + 4), width: nameW, height: nameH },
    role: { x: nameX, y: Math.round(attrY + 4 + nameH), width: nameW, height: roleH },
  };
}

module.exports = {
  QUOTE_GRID_N,
  QUOTE_MARK_COLOR,
  QUOTE_CARD_BORDER,
  quoteMarkInlineSvg,
  quoteGridFrame,
  quoteGridCardGeom,
  quotePortraitGeom,
  quoteTestimonialGeom,
  quoteStatementLeftGeom,
};
