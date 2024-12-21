const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const User = require("../models/user");

// IP 限流
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15分钟
  max: 5, // 每个IP 15分钟内只能注册5次
  message: "操作次数过多，请稍后再试",
});

// 生成 Token 函数
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      role: user.role,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPRIRES_IN,
    }
  );
};

// Token 验证中间件
const authenticateToken = async (req, res, next) => {
  try {
    // 从请求头获取 Token
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (token == null) {
      throw new Error("未提供认证 Token");
    }

    // 验证 Token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 查找用户
    const user = await User.findById(decoded.id).select("-password");
    if (!user) {
      throw new Error("用户不存在");
    }

    // 将用户信息挂载到 req 对象，减少后续重复查询
    req.user = user;
    req.userRole = decoded.role;

    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(400).json({ message: "Token 已过期" });
    }
    return res.status(400).json({ message: error.message });
  }
};

// 角色权限中间件
const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.userRole)) {
      return res.status(403).json({ message: "无权限访问" });
    }
    next();
  };
};

module.exports = {
  generateToken,
  authenticateToken,
  authorizeRoles,
  registerLimiter,
};
