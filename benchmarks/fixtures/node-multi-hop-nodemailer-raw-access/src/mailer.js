import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  streamTransport: true,
  buffer: true,
  disableFileAccess: true,
  disableUrlAccess: true,
});

export function deliverRawMessage(message) {
  return transporter.sendMail({
    from: "scanner@example.test",
    to: message.to,
    raw: message.raw,
  });
}
