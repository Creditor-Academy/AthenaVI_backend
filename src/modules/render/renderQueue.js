/**
 * Runs tasks one at a time in this Node process. A rejected task does not stop the tasks after it.
 * Not shared across processes: keep the backend on a single PM2 instance.
 */
function createSerialQueue() {
  let tail = Promise.resolve();
  let pending = 0;

  function enqueue(task) {
    pending += 1;
    const run = tail.then(() => task());
    tail = run
      .catch(() => undefined)
      .finally(() => {
        pending -= 1;
      });
    return run;
  }

  function size() {
    return pending;
  }

  return { enqueue, size };
}

const renderQueue = createSerialQueue();

module.exports = {
  createSerialQueue,
  renderQueue,
};
