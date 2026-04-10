/*
  Warnings:

  - Made the column `key` on table `Asset` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "Asset" ALTER COLUMN "key" SET NOT NULL,
ALTER COLUMN "updatedAt" DROP DEFAULT;
