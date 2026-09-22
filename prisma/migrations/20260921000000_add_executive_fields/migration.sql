-- Migration to add new fields to Executive model
ALTER TABLE "Executive" ADD COLUMN "identificationNum" TEXT;
ALTER TABLE "Executive" ADD COLUMN "email" TEXT;
ALTER TABLE "Executive" ADD COLUMN "phone" TEXT;
ALTER TABLE "Executive" ADD COLUMN "position" TEXT;
ALTER TABLE "Executive" ADD COLUMN "organization" TEXT;
ALTER TABLE "Executive" ADD COLUMN "emailType" TEXT;
ALTER TABLE "Executive" ADD COLUMN "address" TEXT;
ALTER TABLE "Executive" ADD COLUMN "location" TEXT;
ALTER TABLE "Executive" ADD COLUMN "socialMedia" TEXT;
ALTER TABLE "Executive" ADD COLUMN "notes" TEXT;
ALTER TABLE "Executive" ADD COLUMN "active" BOOLEAN DEFAULT 1;
