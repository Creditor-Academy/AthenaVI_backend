/** Credit routes use :id as workspace UUID; requireWorkspaceRole expects :workspaceId */
function mapCreditWorkspaceId(req, res, next) {
  if (req.params.id && !req.params.workspaceId) {
    req.params.workspaceId = req.params.id;
  }
  next();
}

module.exports = { mapCreditWorkspaceId };
