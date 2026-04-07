const prisma = require("../../shared/config/prismaClient");



const findUserById = (userId) => {
  return prisma.user.findUnique({
    where: { id: userId }
  });
};

  const createAsset = (db,data) => {
    console.log(db,data);
    
    return db.asset.create({ data });
  };

 const incrementUserStorage = (db,userId, size) => {
  return db.user.update({
    where: { id: userId },
    data: {
      storageUsed: {
        increment: size
      }
    }
  });
};


module.exports = {
    findUserById,
    createAsset,
    incrementUserStorage
}