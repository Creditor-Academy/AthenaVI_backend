import React from "react";
import {
  AbsoluteFill,
  useCurrentFrame,
  interpolate,
  spring,
} from "remotion";

export const Scene = ({ text }: { text: string }) => {
  const frame = useCurrentFrame();

  const opacity = interpolate(frame, [0, 20], [0, 1]);
  const scale = spring({
    frame,
    fps: 30,
    from: 0.8,
    to: 1,
  });

  return (
    <AbsoluteFill
      style={{
        justifyContent: "center",
        alignItems: "center",
        backgroundColor: "#020617",
        color: "white",
        fontSize: 60,
      }}
    >
      <div style={{ opacity, transform: `scale(${scale})` }}>
        {text}
      </div>
    </AbsoluteFill>
  );
};