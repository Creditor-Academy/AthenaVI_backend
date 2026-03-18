const jobs = new Map();

async function createJob(data) {
  const id = Date.now().toString();

  const job = {
    id,
    ...data,
    createdAt: new Date(),
  };

  jobs.set(id, job);

  return job;
}

 async function updateJob(id, updates) {
  const job = jobs.get(id);

  if (!job) return null;

  const updated = { ...job, ...updates };

  jobs.set(id, updated);

  return updated;
}

module.exports = {
    createJob,
    updateJob
}