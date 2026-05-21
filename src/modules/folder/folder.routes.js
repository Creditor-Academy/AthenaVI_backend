const express = require('express');

const router = express.Router({ mergeParams: true });
const folderController = require('./folder.controller');
const { folderPermission } = require('../../middlewares/folderPermission');
const validate = require('../../middlewares/validate.middleware');
const folderValidations = require('./folder.validation');

router.post('/', validate(folderValidations.createFolderSchema), folderController.createFolder);
router.get('/', validate(folderValidations.getFoldersSchema), folderController.getFolders);
router.patch(
  '/:folderId',
  validate(folderValidations.renameFolderSchema),
  folderPermission,
  folderController.renameFolder
);
router.delete(
  '/:folderId',
  validate(folderValidations.deleteFolderSchema),
  folderPermission,
  folderController.deleteFolder
);

module.exports = router;