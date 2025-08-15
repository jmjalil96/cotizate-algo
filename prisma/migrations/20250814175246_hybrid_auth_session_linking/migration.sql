/*
  Warnings:

  - You are about to drop the column `isExpired` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `token` on the `Session` table. All the data in the column will be lost.
  - Added the required column `sessionId` to the `RefreshToken` table without a default value. This is not possible if the table is not empty.
  - Added the required column `updatedAt` to the `Session` table without a default value. This is not possible if the table is not empty.

*/
-- DropIndex
DROP INDEX "public"."Session_isExpired_idx";

-- DropIndex
DROP INDEX "public"."Session_token_idx";

-- DropIndex
DROP INDEX "public"."Session_token_key";

-- AlterTable
ALTER TABLE "public"."RefreshToken" ADD COLUMN     "sessionId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "public"."Session" DROP COLUMN "isExpired",
DROP COLUMN "token",
ADD COLUMN     "isActive" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL;

-- CreateIndex
CREATE INDEX "RefreshToken_sessionId_idx" ON "public"."RefreshToken"("sessionId");

-- CreateIndex
CREATE INDEX "Session_isActive_idx" ON "public"."Session"("isActive");

-- AddForeignKey
ALTER TABLE "public"."RefreshToken" ADD CONSTRAINT "RefreshToken_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "public"."Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;
