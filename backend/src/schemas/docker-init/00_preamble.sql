-- NIERS Full Project Schema Init Script
-- MySQL 8.0+
-- Fixed: moved service_cases self-parent rule from CHECK to triggers because MySQL disallows CHECK constraints referencing AUTO_INCREMENT columns.
-- Generated for a database-first NIERS design with intake reports, 999 calls,
-- service cases, emergency incidents, dispatch, disaster/national emergency,
-- facilities, relief, blood support, notifications, workload queues, and audit.

SET NAMES utf8mb4;
SET time_zone = '+00:00';
SET FOREIGN_KEY_CHECKS = 0;
