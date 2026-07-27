const prisma = require('../src/shared/config/prismaClient');

async function main() {
  const user = await prisma.user.findFirst({
    where: { password: { not: null } },
    select: { id: true, email: true, isPlatformSuperadmin: true },
    orderBy: { createdAt: 'asc' },
  });
  console.log('user', JSON.stringify(user));

  const membership = await prisma.workspaceMember.findFirst({
    where: user ? { userId: user.id } : undefined,
    include: {
      workspace: {
        include: { folders: { take: 1, orderBy: { createdAt: 'asc' } } },
      },
    },
  });
  console.log(
    'ctx',
    JSON.stringify(
      membership && {
        workspaceId: membership.workspaceId,
        role: membership.role,
        folderId: membership.workspace.folders[0]?.id || null,
      }
    )
  );

  const videoTpl = await prisma.template.findFirst({
    where: { type: 'VIDEO_SCENE', isActive: true },
    select: { id: true, name: true },
  });
  console.log('videoTpl', JSON.stringify(videoTpl));

  const deckTpl = await prisma.template.findFirst({
    where: { type: 'DECK_LAYOUT', isActive: true },
    select: { id: true, name: true },
  });
  console.log('deckTpl', JSON.stringify(deckTpl));
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
