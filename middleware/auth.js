const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { v4: uuidv4 } = require("uuid");
const User = require("../models/user");

class TokenBlacklist {
  constructor(maxSize = 1000) {
    this.blacklist = new Set();
    this.maxSize = maxSize;
  }
  add(token) {
    if (this.blacklist.size >= this.maxSize) {
      const oldestToken = this.blacklist.values().next().value;
      this.blacklist.delete(oldestToken);
    }
    this.blacklist.add(token);
  }
  has(token) {
    return this.blacklist.has(token);
  }
  remove(token) {
    this.blacklist.delete(token);
  }
  clear() {
    this.blacklist.clear();
  }
  get size() {
    return this.blacklist.size;
  }
}

// token 黑名单
const tokenBlacklist = new TokenBlacklist();

// IP 限流
const IPLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15分钟
  max: 5, // 每个IP 15分钟内只能注册5次
  message: "操作次数过多，请稍后再试",
});

// 生成 token
const generateToken = ({ tokenType = "ACCESS", id, boundIP }) => {
  const jwtOptions =
    tokenType === "ACCESS" ? { id, boundIP } : { id, jwtid: uuidv4() };

  return jwt.sign({ ...jwtOptions }, process.env[`${tokenType}_TOKEN_SECRET`], {
    expiresIn: process.env[`${tokenType}_TOKEN_EXPIRES_IN`],
  });
};

// access token 验证中间件
const verifyAccessToken = async (req, res, next) => {
  try {
    const authAccessToken = req.headers["authorization"];
    const access_token = authAccessToken && authAccessToken.split(" ")[1];

    if (!access_token) {
      throw new jwt.JsonWebTokenError("未提供 access token");
    }

    if (tokenBlacklist.has(access_token)) {
      throw new jwt.JsonWebTokenError("access token 已失效");
    }

    const access_decoded = jwt.verify(
      access_token,
      process.env.ACCESS_TOKEN_SECRET
    );

    const user = await User.findById(access_decoded.id).select("-password");
    if (!user) {
      throw new Error("用户不存在");
    }

    // 将用户信息挂载到 req 对象，减少后续重复查询
    req.access_decoded = { id: user._id, role: user.role };
    req.access_token = access_token;

    next();
  } catch (error) {
    switch (error.name) {
      case "TokenExpiredError":
        return res.status(401).json({
          message: "token 已过期",
        });
      case "JsonWebTokenError":
        return res.status(401).json({
          message: error.message,
        });
      case "NotBeforeError":
        return res.status(401).json({
          message: "token 尚未生效",
        });
      default:
        return res.status(500).json({
          message: error.message,
        });
    }
  }
};

// refresh token 验证中间件
const verifyRefreshToken = async (req, res, next) => {
  try {
    const authRefreshToken = req.headers["authorization-refresh"];
    const refresh_token = authRefreshToken && authRefreshToken.split(" ")[1];

    if (!refresh_token) {
      throw new jwt.JsonWebTokenError("未提供 refresh token");
    }

    if (tokenBlacklist.has(refresh_token)) {
      throw new jwt.JsonWebTokenError("refresh token 已失效");
    }

    const refresh_decoded = jwt.verify(
      refresh_token,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(refresh_decoded.id).select("-password");
    if (!user) {
      throw new Error("用户不存在");
    }

    // 将用户信息挂载到 req 对象，减少后续重复查询
    req.refresh_decoded = { id: user._id, role: user.role };
    req.refresh_token = refresh_token;

    next();
  } catch (error) {
    switch (error.name) {
      case "TokenExpiredError":
        return res.status(401).json({
          message: "token 已过期",
        });
      case "JsonWebTokenError":
        return res.status(401).json({
          message: error.message,
        });
      case "NotBeforeError":
        return res.status(401).json({
          message: "token 尚未生效",
        });
      default:
        return res.status(500).json({
          message: error.message,
        });
    }
  }
};

// 角色权限中间件（需要 token 验证中间件作为前置）
const authorizeRoles = (allowedRoles) => {
  return (req, res, next) => {
    const roleList = [...allowedRoles, "super_admin"];
    if (!roleList.includes(req.token_decoded.role)) {
      return res.status(403).json({ message: "无权限访问" });
    }
    next();
  };
};

module.exports = {
  tokenBlacklist,
  IPLimiter,
  generateToken,
  verifyAccessToken,
  verifyRefreshToken,
  authorizeRoles,
};
