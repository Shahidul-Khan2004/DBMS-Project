import "dotenv/config";
import { createApp } from "./createApp.js";
import { bootstrapDevelopmentSystemAdmin } from "./services/bootstrapService.js";
import { startEmailQueueWorker } from "./workers/emailQueueWorker.js";

const PORT = process.env.PORT || 8080;
const app = createApp();

async function startServer() {
  try {
    await bootstrapDevelopmentSystemAdmin();
  } catch (error) {
    console.error("Bootstrap failed:", error);
  }

 startEmailQueueWorker();

  app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}`);
  });
}

startServer();
