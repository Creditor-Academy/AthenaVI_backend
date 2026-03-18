import React from "react";
import { Composition } from "remotion";
import { Scene } from "./scene";

export const RemotionRoot = () => {
  return (
    <Composition
      id="Scene"
      component={Scene}
      durationInFrames={300}
      fps={30}
      width={1280}
      height={720}
      defaultProps={{ text: "Hello" }}
    />
  );
};