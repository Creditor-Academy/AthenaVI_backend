const React = require('react');
const { Composition, registerRoot } = require('remotion');
const { SceneComposition } = require('./SceneComposition');
const { ProjectRenderComposition } = require('./ProjectRenderComposition');
const { buildSceneTimings } = require('./transitions');

function RemotionRoot() {
  return (
    <>
      <Composition
        id="SceneComposition"
        component={SceneComposition}
        defaultProps={{
          scene: {
            durationInFrames: 1,
            background: { type: 'color', value: '#000000' },
            elements: [],
          },
        }}
        durationInFrames={1}
        fps={30}
        width={1920}
        height={1080}
        calculateMetadata={({ props }) => ({
          durationInFrames: Math.max(props.scene?.durationInFrames || 1, 1),
          fps: props.videoSettings?.fps || 30,
          width: props.videoSettings?.width || 1920,
          height: props.videoSettings?.height || 1080,
        })}
      />
      <Composition
        id="ProjectRenderComposition"
        component={ProjectRenderComposition}
        defaultProps={{
          videoSettings: {
            width: 1920,
            height: 1080,
            fps: 30,
            backgroundColor: '#000000',
          },
          scenes: [],
        }}
        durationInFrames={1}
        fps={30}
        width={1920}
        height={1080}
        calculateMetadata={({ props }) => ({
          durationInFrames: buildSceneTimings(props.scenes || []).durationInFrames,
          fps: props.videoSettings?.fps || 30,
          width: props.videoSettings?.width || 1920,
          height: props.videoSettings?.height || 1080,
        })}
      />
    </>
  );
}

registerRoot(RemotionRoot);
