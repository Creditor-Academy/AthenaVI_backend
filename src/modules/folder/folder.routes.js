const express = require('express');

const router = express.Router({ mergeParams: true });
const folderController = require('./folder.controller');
const { folderPermission } = require('../../middlewares/folderPermission');

router.post('/', folderController.createFolder )
router.get('/', folderController.getFolders)
router.patch('/:folderId', folderPermission, folderController.renameFolder);
router.delete('/:folderId', folderPermission, folderController.deleteFolder);

module.exports = router;