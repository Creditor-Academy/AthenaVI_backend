-- Canva-parity: durable system media for DECK_LAYOUT / DECK_PACK templates
CREATE TABLE "template_media" (
    "id" TEXT NOT NULL,
    "template_id" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "slot_hint" TEXT,
    "name" TEXT,
    "s3_key" TEXT NOT NULL,
    "mime_type" TEXT,
    "sort_order" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "template_media_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "template_media_template_id_slot_hint_key" ON "template_media"("template_id", "slot_hint");

CREATE INDEX "template_media_template_id_kind_idx" ON "template_media"("template_id", "kind");

ALTER TABLE "template_media" ADD CONSTRAINT "template_media_template_id_fkey" FOREIGN KEY ("template_id") REFERENCES "templates"("id") ON DELETE CASCADE ON UPDATE CASCADE;
