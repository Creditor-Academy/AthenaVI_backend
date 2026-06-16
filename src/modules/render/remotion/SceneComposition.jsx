const React = require('react');
const {
  AbsoluteFill,
  Audio,
  Img,
  OffthreadVideo,
  Sequence,
  useCurrentFrame,
  useVideoConfig,
} = require('remotion');
const {
  buildAnimatedStyle,
  resolveAnimatedText,
} = require('./animations');
const { DELAY_RENDER_TIMEOUT_MS } = require('./renderTimeouts');

function BackgroundLayer({ background }) {
  if (!background || background.type === 'color') {
    return <AbsoluteFill style={{ backgroundColor: background?.value || '#000000' }} />;
  }

  if ((background.type === 'image' || background.type === 'asset-image') && background.src) {
    return (
      <AbsoluteFill>
        <Img
          src={background.src}
          delayRenderTimeoutInMilliseconds={DELAY_RENDER_TIMEOUT_MS}
          style={{ width: '100%', height: '100%', objectFit: background.fit || 'cover' }}
        />
      </AbsoluteFill>
    );
  }

  if ((background.type === 'video' || background.type === 'asset-video') && background.src) {
    return (
      <AbsoluteFill>
        <OffthreadVideo
          src={background.src}
          delayRenderTimeoutInMilliseconds={DELAY_RENDER_TIMEOUT_MS}
          style={{ width: '100%', height: '100%', objectFit: background.fit || 'cover' }}
        />
      </AbsoluteFill>
    );
  }

  return <AbsoluteFill style={{ backgroundColor: '#000000' }} />;
}

function TextLikeElement({ element, frame, fps }) {
  const content = element.content || {};
  const style = element.style && typeof element.style === 'object' ? element.style : {};
  const typography = { ...content, ...style };
  const text = resolveAnimatedText({
    frame,
    text: content.text || '',
    animations: element.animations,
  });

  const textDecoration =
    typography.textDecoration ||
    (typography.underline === true ? 'underline' : undefined) ||
    typography.textDecorationLine;

  return (
    <div
      style={{
        ...buildAnimatedStyle({
          frame,
          fps,
          placement: element.placement,
          animations: element.animations,
        }),
        display: 'flex',
        alignItems: 'center',
        justifyContent:
          typography.textAlign === 'center'
            ? 'center'
            : typography.textAlign === 'right'
              ? 'flex-end'
              : 'flex-start',
        whiteSpace: typography.whiteSpace || 'pre-wrap',
        fontFamily: typography.fontFamily || 'sans-serif',
        fontSize: typography.fontSize || 32,
        fontWeight: typography.fontWeight || (typography.bold === true ? 700 : 400),
        fontStyle: typography.fontStyle || (typography.italic === true ? 'italic' : 'normal'),
        color: typography.color || '#FFFFFF',
        lineHeight: typography.lineHeight || 1.2,
        textAlign: typography.textAlign || 'left',
        textTransform: typography.textTransform || 'none',
        letterSpacing: typography.letterSpacing,
        padding: typography.padding,
        backgroundColor:
          typography.backgroundColor && typography.backgroundColor !== 'transparent'
            ? typography.backgroundColor
            : undefined,
        textDecoration,
        textShadow: typography.textShadow,
        boxShadow: typography.boxShadow,
      }}
    >
      {text}
    </div>
  );
}

function isFrameElement(element) {
  const content = element.content || {};
  return element.role === 'frame' || content.frame === true;
}

function IconElement({ element, frame, fps }) {
  const content = element.content || {};
  const style = element.style && typeof element.style === 'object' ? element.style : {};
  const filters = element.filters && typeof element.filters === 'object' ? element.filters : {};

  return (
    <div
      style={{
        ...buildAnimatedStyle({
          frame,
          fps,
          placement: element.placement,
          animations: element.animations,
        }),
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        overflow: 'hidden',
        backgroundColor: style.backgroundColor || 'transparent',
        borderRadius: style.borderRadius || '50%',
        boxShadow: style.boxShadow,
        padding: style.padding,
        filter: buildCssFilterString(filters),
      }}
    >
      <Img
        src={content.src}
        delayRenderTimeoutInMilliseconds={DELAY_RENDER_TIMEOUT_MS}
        style={{
          width: '100%',
          height: '100%',
          objectFit: style.objectFit || content.fit || 'contain',
          filter: buildCssFilterString(content.filters),
        }}
      />
    </div>
  );
}

function FrameElement({ element, frame, fps }) {
  const content = element.content || {};
  const style = element.style && typeof element.style === 'object' ? element.style : {};
  const fill = content.fill && typeof content.fill === 'object' ? content.fill : null;
  const fillSrc = fill?.src;
  const objectFit = fill?.objectFit || fill?.fit || 'cover';

  const containerStyle = {
    ...buildAnimatedStyle({
      frame,
      fps,
      placement: element.placement,
      animations: element.animations,
    }),
    overflow: 'hidden',
    backgroundColor: style.backgroundColor || '#e2e8f0',
    borderRadius: style.borderRadius || 0,
    clipPath: style.clipPath,
    border: style.border || 'none',
    boxShadow: style.boxShadow,
  };

  if (fillSrc) {
    return (
      <div style={containerStyle}>
        <Img src={fillSrc} delayRenderTimeoutInMilliseconds={DELAY_RENDER_TIMEOUT_MS} style={{ width: '100%', height: '100%', objectFit }} />
      </div>
    );
  }

  return <div style={containerStyle} />;
}

function ShapeElement({ element, frame, fps }) {
  if (isFrameElement(element)) {
    return <FrameElement element={element} frame={frame} fps={fps} />;
  }

  const content = element.content || {};
  const style = element.style && typeof element.style === 'object' ? element.style : {};
  const fill =
    typeof content.fill === 'string' || typeof content.fill === 'number'
      ? content.fill
      : (content.backgroundColor ?? style.backgroundColor);
  const shapeStyle = getMediaShapeStyle(content, element.placement);
  return (
    <div
      style={{
        ...buildAnimatedStyle({
          frame,
          fps,
          placement: element.placement,
          animations: element.animations,
        }),
        backgroundColor: fill == null || fill === '' ? 'transparent' : fill,
        clipPath: style.clipPath,
        ...shapeStyle,
        borderRadius: content.borderRadius ?? style.borderRadius ?? shapeStyle.borderRadius ?? 0,
        border: content.border || style.border || 'none',
        boxShadow: style.boxShadow,
      }}
    />
  );
}

function getMediaShapeStyle(content = {}, placement = {}) {
  const explicitRadius = content.borderRadius;
  const shape = typeof content.shape === 'string' ? content.shape.trim().toLowerCase() : '';
  const width = Number(placement.width) || 0;
  const height = Number(placement.height) || 0;
  const minSide = Math.min(width, height);

  if (explicitRadius != null && explicitRadius !== '') {
    return { borderRadius: explicitRadius };
  }

  if (shape === 'circle') {
    return { borderRadius: minSide > 0 ? minSide / 2 : 9999 };
  }
  if (shape === 'rounded') {
    return { borderRadius: 24 };
  }
  if (shape === 'square') {
    return { borderRadius: 0 };
  }
  if (shape === 'squircle') {
    return { borderRadius: 36 };
  }

  return {};
}

function buildCssFilterString(filters) {
  if (!filters || typeof filters !== 'object') {
    return undefined;
  }

  const parts = [];
  const {
    brightness,
    contrast,
    saturate,
    blur,
    grayscale,
    sepia,
    hueRotate,
    invert,
    opacity: filterOpacity,
  } = filters;

  if (brightness != null && Number(brightness) !== 1) {
    parts.push(`brightness(${brightness})`);
  }
  if (contrast != null && Number(contrast) !== 1) {
    parts.push(`contrast(${contrast})`);
  }
  if (saturate != null && Number(saturate) !== 1) {
    parts.push(`saturate(${saturate})`);
  }
  if (blur != null && Number(blur) > 0) {
    parts.push(`blur(${blur}px)`);
  }
  if (grayscale != null && Number(grayscale) > 0) {
    parts.push(`grayscale(${grayscale})`);
  }
  if (sepia != null && Number(sepia) > 0) {
    parts.push(`sepia(${sepia})`);
  }
  if (hueRotate != null && Number(hueRotate) !== 0) {
    parts.push(`hue-rotate(${hueRotate}deg)`);
  }
  if (invert != null && Number(invert) > 0) {
    parts.push(`invert(${invert})`);
  }
  if (filterOpacity != null && Number(filterOpacity) !== 1) {
    parts.push(`opacity(${filterOpacity})`);
  }

  return parts.length > 0 ? parts.join(' ') : undefined;
}

function buildFlipTransform(content = {}) {
  const scaleX = content.flipHorizontal ? -1 : 1;
  const scaleY = content.flipVertical ? -1 : 1;
  if (scaleX === 1 && scaleY === 1) {
    return undefined;
  }
  return `scale(${scaleX}, ${scaleY})`;
}

function MediaElement({ element, frame, fps }) {
  const content = element.content || {};
  const containerStyle = {
    ...buildAnimatedStyle({
      frame,
      fps,
      placement: element.placement,
      animations: element.animations,
    }),
    overflow: 'hidden',
    ...getMediaShapeStyle(content, element.placement),
  };
  const mediaStyle = {
    width: '100%',
    height: '100%',
    objectFit: content.fit || 'contain',
    filter: buildCssFilterString(content.filters),
    transform: buildFlipTransform(content),
  };

  switch (element.type) {
    case 'avatar':
    case 'video':
      return (
        <div style={containerStyle}>
          <OffthreadVideo
            src={element.content?.src}
            delayRenderTimeoutInMilliseconds={DELAY_RENDER_TIMEOUT_MS}
            style={mediaStyle}
          />
        </div>
      );
    case 'image':
      return (
        <div style={containerStyle}>
          <Img
            src={element.content?.src}
            delayRenderTimeoutInMilliseconds={DELAY_RENDER_TIMEOUT_MS}
            style={mediaStyle}
          />
        </div>
      );
    case 'audio':
      return <Audio src={element.content?.src} delayRenderTimeoutInMilliseconds={DELAY_RENDER_TIMEOUT_MS} />;
    default:
      return null;
  }
}

function SceneElement({ element }) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  if (element.visible === false) {
    return null;
  }

  if (element.type === 'text' || element.type === 'subtitle') {
    return <TextLikeElement element={element} frame={frame} fps={fps} />;
  }

  if (element.type === 'icon') {
    return <IconElement element={element} frame={frame} fps={fps} />;
  }

  if (element.type === 'shape') {
    return <ShapeElement element={element} frame={frame} fps={fps} />;
  }

  return <MediaElement element={element} frame={frame} fps={fps} />;
}

function SceneComposition({ scene }) {
  return (
    <AbsoluteFill style={{ backgroundColor: '#000000', overflow: 'hidden' }}>
      <BackgroundLayer background={scene.background} />
      {(scene.elements || [])
        .slice()
        .sort((a, b) => a.layer - b.layer)
        .map((element) => (
          <Sequence
            key={element.id}
            from={element.startFrame || 0}
            durationInFrames={element.durationInFrames}
          >
            <SceneElement element={element} />
          </Sequence>
        ))}
    </AbsoluteFill>
  );
}

module.exports = {
  SceneComposition,
};
