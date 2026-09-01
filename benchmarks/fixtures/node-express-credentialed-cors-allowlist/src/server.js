import express from "express";
import cors from "cors";
import session from "express-session";

const app = express();

const corsOptions = {
  origin: "https://app.example",
  credentials: true,
};

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: "lax" },
}));
app.use(cors(corsOptions));

function readAccount(request, response) {
  return response.json({
    email: request.session.account.email,
    roles: request.session.account.roles,
  });
}

app.get("/account", readAccount);

export { app };
