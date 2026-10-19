const bcrypt = require('bcrypt');
const prisma = require('../src/shared/config/prismaClient');

const EMAIL = 'api.smoke.videotemplates@example.com';
const PASSWORD = 'SmokeTest123!';

async function main() {
  const hash = await bcrypt.hash(PASSWORD, 10);
  let user = await prisma.user.findUnique({ where: { email: EMAIL } });
  if (!user) {
    user = await prisma.user.create({
      data: {
        email: EMAIL,
        name: 'API Smoke Tester',
        password: hash,
        emailVerified: true,
        credits: 10000,
        isPlatformSuperadmin: true,
      },
    });
    console.log('created-user', user.id);
  } else {
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hash,
        emailVerified: true,
        isPlatformSuperadmin: true,
        credits: 10000,
      },
    });
    console.log('updated-user', user.id);
  }

  let workspace = await prisma.workspace.findFirst({
    where: { ownerId: user.id },
  });
  if (!workspace) {
    workspace = await prisma.workspace.create({
      data: {
        name: 'Smoke Test Workspace',
        type: 'PRIVATE',
        ownerId: user.id,
        members: {
          create: { userId: user.id, role: 'OWNER' },
        },
      },
    });
    console.log('created-workspace', workspace.id);
  } else {
    console.log('workspace', workspace.id);
  }

  let folder = await prisma.folder.findFirst({
    where: { workspaceId: workspace.id },
  });
  if (!folder) {
    folder = await prisma.folder.create({
      data: {
        name: 'Smoke Folder',
        workspaceId: workspace.id,
        createdBy: user.id,
      },
    });
    console.log('created-folder', folder.id);
  } else {
    console.log('folder', folder.id);
  }

  const videoTpl = await prisma.template.findFirst({
    where: { type: 'VIDEO_SCENE', isActive: true },
    select: { id: true, name: true },
  });

  console.log(
    JSON.stringify({
      email: EMAIL,
      password: PASSWORD,
      userId: user.id,
      workspaceId: workspace.id,
      folderId: folder.id,
      videoTemplateId: videoTpl?.id || null,
    })
  );
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
