const prisma = require('../../shared/config/prismaClient');

const findFolderById = async (folderId) => {
  return await prisma.folder.findUnique({
    where: { id: folderId },
  });
};

const createProject = async (projectData) => {
  return await prisma.project.create({
    data: projectData,
  });
};

module.exports = {
  findFolderById,
  createProject,
};
