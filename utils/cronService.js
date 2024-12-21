const cron = require("node-cron");
const User = require("../models/user");

class CronService {
  constructor() {
    this.cronExpression = process.env.SCHEDULE_CRON || "0 2 * * *";
    this.isEnabled = process.env.IS_CRON_SERVICE === "true";
  }

  startCleanupAccount() {
    if (!this.isEnabled) {
      console.log("Cron 定时服务已关闭");
      return;
    }

    cron.schedule(this.cronExpression, async () => {
      try {
        const daysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

        const result = await User.deleteMany({
          role: "visitor",
          lastActiveAt: { $lt: daysAgo },
        });

        console.log(`清理未活跃游客账号：${result.deletedCount} 个`);
      } catch (error) {
        console.error("游客账号清理失败:", error);
      }
    });

    console.log(`Cleanup cron started: ${this.cronExpression}`);
  }
}

module.exports = new CronService();
