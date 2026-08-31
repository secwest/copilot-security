import express from "express";

const app = express();

app.get("/continue", (req, res) => {
  const target = req.query.next;
  return res.redirect("/" + target);
});

export default app;
