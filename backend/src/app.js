import "dotenv/config";
import express from "express";
import healthRouter from "./api/routes/health.js";
import authRouter from "./api/routes/auth.js";
import usersRouter from "./api/routes/users.js";
import { errorHandler, notFound } from "./api/middlewares/error.js";
import { bootstrapDevelopmentSystemAdmin } from "./services/bootstrapService.js";

const app = express();

const PORT = process.env.PORT || 8080;

app.use(express.json());

app.use("/", healthRouter);
app.use("/auth", authRouter);
app.use("/users", usersRouter);

app.use(notFound);

//error handler should be the last middleware
app.use(errorHandler);

async function startServer() {
  try {
    await bootstrapDevelopmentSystemAdmin();
  } catch (error) {
    console.error("Bootstrap failed:", error);
  }

  app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}`);
  });
}

startServer();
