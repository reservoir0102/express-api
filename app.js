require("dotenv").config(); // 加载环境变量文件，并挂载到 process.env

const createError = require("http-errors");
const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const logger = require("morgan");
const mongoose = require("mongoose");

const indexRouter = require("./routes/index");
const usersRouter = require("./routes/users");

const User = require("./models/user");
const cronService = require("./utils/cronService");

const app = express();

// 模板引擎
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "jade");

// 日志打印
if (process.env.LOG_COLORS) {
  app.use(logger("dev"));
} else {
  app.use(
    logger("combined", {
      stream: {
        write: (message) => {
          console.log(message.trim());
        },
      },
    })
  );
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.use("/", indexRouter);
app.use("/users", usersRouter);

// 数据库连接
mongoose
  .connect(process.env.MONGODB_URI || "mongodb://localhost:27017/wooden-blog")
  .then(async () => {
    console.log("MongoDB 连接成功!");

    // 检查是否存在超级管理员账号
    const superAdminCount = await User.countDocuments({ role: "super_admin" });
    if (superAdminCount === 0) {
      try {
        const initialAdmin = new User({
          account: process.env.SUPER_ADMIN_ACCOUNT || "woodenclub.cn",
          password: process.env.SUPER_ADMIN_PASSWORD || "WoodenBlog2024",
          role: "super_admin",
        });

        await initialAdmin.save();
        console.log("超级管理员创建成功!");
      } catch (error) {
        console.error("超级管理员创建失败:", error);
      }
    }
  })
  .catch((err) => {
    console.error("MongoDB 连接失败:", err);
    process.exit(1); // 连接失败则退出进程
  });

// 定时任务
mongoose.connection.on("connected", () => {
  cronService.startCleanupAccount();
});

// 捕获 404 错误，并转发到错误处理中间件
app.use(function (req, res, next) {
  next(createError(404));
});

// 错误处理中间件
app.use(function (err, req, res, next) {
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  res.status(err.status || 500);
  res.render("error");
});

module.exports = app;
