import express from "express";
import jwt from "jsonwebtoken";

const app = express();

const sessionCookie = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
};

function issueSession(request, response) {
  const token = jwt.sign(
    { sub: request.user.id },
    process.env.JWT_SIGNING_KEY,
    { expiresIn: "15m" },
  );
  return response
    .cookie("__Host-session", token, sessionCookie)
    .status(204)
    .end();
}

app.post("/session", issueSession);

export { app };
