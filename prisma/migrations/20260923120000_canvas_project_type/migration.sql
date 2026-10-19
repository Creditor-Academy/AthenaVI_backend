-- Add CANVAS as a Project type so the design-canvas editor can persist its own
-- documents (folder-scoped, like VIDEO/PRESENTATION) without a new table.
ALTER TYPE "ProjectType" ADD VALUE 'CANVAS';
