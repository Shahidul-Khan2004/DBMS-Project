/**
 * integrations/mailer.js
 * ======================
 * Nodemailer transporter configured from environment variables.
 *
 * This module creates and exports a single shared transporter instance.
 * It is used exclusively by emailWorkerService.js — nothing else should
 * import this directly.
 *
 * Environment variables required:
 *   MAIL_HOST  - SMTP host      (e.g. sandbox.smtp.mailtrap.io)
 *   MAIL_PORT  - SMTP port      (e.g. 2525)
 *   MAIL_USER  - SMTP username
 *   MAIL_PASS  - SMTP password
 *   MAIL_FROM  - Sender address (e.g. noreply@niers.local)
 */

import nodemailer from "nodemailer";

// Single shared transporter — created once when the module is first imported.
// Nodemailer manages the underlying SMTP connection pool internally.
const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: Number(process.env.MAIL_PORT),

  // secure: false means STARTTLS (used by Mailtrap on port 2525).
  // Set to true only when using port 465 (SSL).
  secure: false,

  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

/**
 * Sends a single email.
 *
 * @param {object} params
 * @param {string} params.to      - Recipient email address
 * @param {string} params.subject - Email subject line
 * @param {string} params.text    - Plain-text email body
 *
 * @returns {Promise<object>} Nodemailer send info object (includes messageId)
 * @throws Will throw if the SMTP connection or send fails
 */
export async function sendEmail({ to, subject, text }) {
  return transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject,
    text,
  });
}