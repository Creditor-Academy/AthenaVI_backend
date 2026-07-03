-- CreateEnum
CREATE TYPE "ProductEmailBroadcastRecipientStatus" AS ENUM ('SENT', 'FAILED');

-- CreateTable
CREATE TABLE "product_email_broadcasts" (
    "id" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "html_body" TEXT NOT NULL,
    "text_body" TEXT,
    "sent_by_user_id" TEXT NOT NULL,
    "recipient_count" INTEGER NOT NULL,
    "sent_count" INTEGER NOT NULL,
    "failed_count" INTEGER NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "product_email_broadcasts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "product_email_broadcast_recipients" (
    "id" TEXT NOT NULL,
    "broadcast_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "status" "ProductEmailBroadcastRecipientStatus" NOT NULL,
    "error" TEXT,
    "sent_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "product_email_broadcast_recipients_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "product_email_broadcasts_created_at_idx" ON "product_email_broadcasts"("created_at");

-- CreateIndex
CREATE INDEX "product_email_broadcasts_sent_by_user_id_idx" ON "product_email_broadcasts"("sent_by_user_id");

-- CreateIndex
CREATE INDEX "product_email_broadcast_recipients_broadcast_id_idx" ON "product_email_broadcast_recipients"("broadcast_id");

-- CreateIndex
CREATE INDEX "product_email_broadcast_recipients_user_id_idx" ON "product_email_broadcast_recipients"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "product_email_broadcast_recipients_broadcast_id_user_id_key" ON "product_email_broadcast_recipients"("broadcast_id", "user_id");

-- AddForeignKey
ALTER TABLE "product_email_broadcasts" ADD CONSTRAINT "product_email_broadcasts_sent_by_user_id_fkey" FOREIGN KEY ("sent_by_user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "product_email_broadcast_recipients" ADD CONSTRAINT "product_email_broadcast_recipients_broadcast_id_fkey" FOREIGN KEY ("broadcast_id") REFERENCES "product_email_broadcasts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "product_email_broadcast_recipients" ADD CONSTRAINT "product_email_broadcast_recipients_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
