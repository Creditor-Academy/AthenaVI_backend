-- CreateEnum
CREATE TYPE "InterfaceMode" AS ENUM ('LIGHT', 'DARK');

-- CreateEnum
CREATE TYPE "ThemePalette" AS ENUM ('ORIGINAL', 'SAPPHIRE', 'OCEAN', 'FOREST', 'SUNSET', 'CUSTOM');

-- CreateTable
CREATE TABLE "user_settings" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "interface_mode" "InterfaceMode" NOT NULL DEFAULT 'LIGHT',
    "theme_palette" "ThemePalette" NOT NULL DEFAULT 'SAPPHIRE',
    "custom_accent_color" TEXT NOT NULL DEFAULT '#2563EB',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_settings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_settings_user_id_key" ON "user_settings"("user_id");

-- CreateIndex
CREATE INDEX "user_settings_user_id_idx" ON "user_settings"("user_id");

-- AddForeignKey
ALTER TABLE "user_settings" ADD CONSTRAINT "user_settings_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
