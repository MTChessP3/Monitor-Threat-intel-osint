-- Add new columns to Executive table
ALTER TABLE "Executive" ADD COLUMN "socialMedia" TEXT DEFAULT '[]';
ALTER TABLE "Executive" ADD COLUMN "address" TEXT;
ALTER TABLE "Executive" ADD COLUMN "location" TEXT;
ALTER TABLE "Executive" ADD COLUMN "emailType" TEXT DEFAULT 'personal';
