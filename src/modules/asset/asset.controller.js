const { successResponse } = require("../../shared/utils/apiResponse");
const asyncHandler = require("../../shared/utils/asyncHandler");
const messages = require("../../shared/utils/messages");
const assetService = require("./asset.service");


const uploadAsset = asyncHandler(async(req,res)=>{
    const userId = req.user.id;
    const file = req.file; 
    const workspace = req.workspace;

    const asset = await assetService.uploadAsset({
        userId,
        workspace,
        file
    });

    return successResponse(req, res, { asset }, 201, messages.ASSET_UPLOADED_SUCCESSFULLY);

})


module.exports = {
    uploadAsset
}