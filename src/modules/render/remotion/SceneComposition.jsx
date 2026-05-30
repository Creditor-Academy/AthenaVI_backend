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

function BackgroundLayer({ background }) {
  if (!background || background.type === 'color') {
    return <AbsoluteFill style={{ backgroundColor: background?.value || '#000000' }} />;
  }

  if ((background.type === 'image' || background.type === 'asset-image') && background.src) {
    return (
      <AbsoluteFill>
        <Img
          src={background.src}
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

function ShapeElement({ element, frame, fps }) {
  const content = element.content || {};
  return (
    <div
      style={{
        ...buildAnimatedStyle({
          frame,
          fps,
          placement: element.placement,
          animations: element.animations,
        }),
        backgroundColor: content.fill || '#FFFFFF',
        borderRadius: content.borderRadius || 0,
        border: content.border || 'none',
      }}
    />
  );
}

function MediaElement({ element, frame, fps }) {
  const baseStyle = {
    ...buildAnimatedStyle({
      frame,
      fps,
      placement: element.placement,
      animations: element.animations,
    }),
    objectFit: element.content?.fit || 'contain',
  };

  switch (element.type) {
    case 'avatar':
    case 'video':
      return <OffthreadVideo src={element.content?.src} style={baseStyle} />;
    case 'image':
      return <Img src={element.content?.src} style={baseStyle} />;
    case 'audio':
      return <Audio src={element.content?.src} />;
    default:
      return null;
  }
}

function SceneElement({ element }) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  if (element.type === 'text' || element.type === 'subtitle') {
    return <TextLikeElement element={element} frame={frame} fps={fps} />;
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
