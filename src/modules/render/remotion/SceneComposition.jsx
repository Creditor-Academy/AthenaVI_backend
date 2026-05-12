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
  const text = resolveAnimatedText({
    frame,
    text: content.text || '',
    animations: element.animations,
  });

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
          content.textAlign === 'center'
            ? 'center'
            : content.textAlign === 'right'
              ? 'flex-end'
              : 'flex-start',
        whiteSpace: 'pre-wrap',
        fontFamily: content.fontFamily || 'sans-serif',
        fontSize: content.fontSize || 32,
        fontWeight: content.fontWeight || 400,
        color: content.color || '#FFFFFF',
        lineHeight: content.lineHeight || 1.2,
        textAlign: content.textAlign || 'left',
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
