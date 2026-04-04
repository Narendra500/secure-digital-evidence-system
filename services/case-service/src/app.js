import express from "express";
import caseRoutes from "./routes/caseRoutes.js";

const app = express();

app.use(express.json());

// health check (optional)
app.get("/", (req, res) => {
  res.send("Case Service API running");
});

// mount case routes
app.use("/cases", caseRoutes);

export default app;