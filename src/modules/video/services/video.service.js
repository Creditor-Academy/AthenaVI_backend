// const { generateAvatarVideo } = require("./heygen.service");

// async function generateVideo(timeline) {
//   if (!timeline || !Array.isArray(timeline.scenes)) {
//     throw new Error("Invalid timeline format");
//   }

//   const avatarTasks = [];

//   timeline.scenes.forEach((scene, sceneIndex) => {
//     if (!scene.elements) return;

//     scene.elements.forEach((element, elementIndex) => {
//       if (element.type === "avatar") {
//         avatarTasks.push({
//           sceneIndex,
//           elementIndex,
//           avatarId: element.avatarId,
//           script: element.script
//         });
//       }
//     });
//   });

//   console.log("🧠 Avatar Tasks:", avatarTasks);

//   // 3️⃣ Generate avatars in parallel
//   const avatarResults = await Promise.all(
//     avatarTasks.map((task) => generateAvatarVideo(task))
//   );

//   console.log("🎬 Avatar Videos:", avatarResults);

//   // TEMP return (next step will patch timeline)
//   return {
//     avatarResults
//   };
// }

// module.exports = { generateVideo };