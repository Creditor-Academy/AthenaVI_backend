const React = require('react');
const {
  AbsoluteFill,
  OffthreadVideo,
  Sequence,
  useCurrentFrame,
  useVideoConfig,
} = require('remotion');
const {
  buildSceneTimings,
  getSceneTransitionStyle,
} = require('./transitions');

function SceneClip({ scene }) {
  const frame = useCurrentFrame();
  const { width, height } = useVideoConfig();
  const transitionStyle = getSceneTransitionStyle({
    frame,
    scene,
    width,
    height,
  });

  return (
    <AbsoluteFill
      style={{
        backgroundColor: transitionStyle.wipeColor || 'transparent',
      }}
    >
      <AbsoluteFill
        style={{
          opacity: transitionStyle.opacity,
          clipPath: transitionStyle.clipPath,
          filter: transitionStyle.filter,
          transform: transitionStyle.transform,
        }}
      >
        <OffthreadVideo
          src={scene.src}
          style={{ width: '100%', height: '100%', objectFit: 'cover' }}
        />
      </AbsoluteFill>
    </AbsoluteFill>
  );
}

function ProjectRenderComposition({ scenes = [], videoSettings = {} }) {
  const timeline = buildSceneTimings(scenes);

  return (
    <AbsoluteFill style={{ backgroundColor: videoSettings.backgroundColor || '#000000' }}>
      {timeline.scenes.map((scene) => (
        <Sequence
          key={scene.sceneId}
          from={scene.startFrame}
          durationInFrames={scene.durationInFrames}
        >
          <SceneClip scene={scene} />
        </Sequence>
      ))}
    </AbsoluteFill>
  );
}

module.exports = {
  ProjectRenderComposition,
};
