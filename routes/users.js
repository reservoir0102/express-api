const express = require("express");
const User = require("../models/user");
const {
  verifyAccessToken,
  verifyRefreshToken,
  generateToken,
  tokenBlacklist,
  IPLimiter,
} = require("../middleware/auth");
const { validateParams } = require("../middleware/validate");

const router = express.Router();

// 游客登录
router.post(
  "/visitor-login",
  IPLimiter,
  validateParams(["account", "password"]),
  async (req, res, next) => {
    try {
      const { account, password, nickname } = req.body;
      const user = await User.findOne({ account });
      let newUser;

      if (user) {
        if (user.role !== "visitor") {
          return res
            .status(403)
            .json({ message: "账号权限不适合访问当前接口" });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
          throw new Error("密码错误");
        }

        if (user.status === "suspended") {
          throw new Error("账号已被禁用");
        }

        newUser = user;
        newUser.lastActiveAt = new Date();
        await newUser.save();
      } else {
        newUser = new User({
          account,
          password,
          profile: { nickname },
        });
        await newUser.save();
      }

      const access_token = generateToken({
        tokenType: "ACCESS",
        id: newUser._id,
        boundIP: req.ip,
      });
      const refresh_token = generateToken({
        tokenType: "REFRESH",
        id: newUser._id,
      });

      res.status(200).json({
        message: "游客登录成功",
        access_token,
        refresh_token,
        user: {
          id: newUser._id,
          account: newUser.account,
          role: newUser.role,
          ...newUser.profile,
        },
      });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }
);

// 登录
router.post(
  "/login",
  validateParams(["account", "password"]),
  async (req, res, next) => {
    try {
      const { account, password } = req.body;
      const user = await User.findOne({ account });

      if (!user) {
        throw new Error("用户不存在");
      }

      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        throw new Error("密码错误");
      }

      if (user.status === "suspended") {
        throw new Error("账号已被禁用");
      }

      user.lastActiveAt = new Date();
      await user.save();

      const access_token = generateToken({
        tokenType: "ACCESS",
        id: user._id,
        boundIP: req.ip,
      });
      const refresh_token = generateToken({
        tokenType: "REFRESH",
        id: user._id,
      });

      res.status(200).json({
        message: "登录成功",
        access_token,
        refresh_token,
        user: {
          id: user._id,
          account: user.account,
          role: user.role,
          ...user.profile,
        },
      });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }
);

// 退出登录
router.post("/logout", verifyRefreshToken, async (req, res, next) => {
  try {
    const authAccessToken = req.headers["authorization"];
    const access_token = authAccessToken && authAccessToken.split(" ")[1];

    if (access_token) {
      tokenBlacklist.add(access_token);
    }

    tokenBlacklist.add(req.refresh_token);

    res.status(200).json({ message: "退出登录成功" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// 注册
router.post(
  "/register",
  IPLimiter,
  validateParams(["account", "password"]),
  async (req, res, next) => {
    try {
      const { account, password, role = "visitor" } = req.body;
      const existingUser = await User.findOne({ account });

      if (existingUser) {
        throw new Error("账号已被注册");
      }

      const user = new User({ account, password, role });
      await user.save();

      const access_token = generateToken({
        tokenType: "ACCESS",
        id: user._id,
        boundIP: req.ip,
      });
      const refresh_token = generateToken({
        tokenType: "REFRESH",
        id: user._id,
      });

      res
        .status(200)
        .json({ message: "注册成功", access_token, refresh_token });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }
);

// 修改个人信息
router.put("/profile", verifyAccessToken, async (req, res, next) => {
  try {
    const profile = req.body;
    const user = await User.findById(req.access_decoded.id);

    user.profile = { ...user.profile, ...profile };
    await user.save();

    res.status(200).json({
      message: "账号信息修改成功",
      user: {
        id: user._id,
        account: user.account,
        role: user.role,
        ...user.profile,
      },
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// 修改密码
router.put(
  "/password",
  validateParams(["password"]),
  verifyAccessToken,
  async (req, res, next) => {
    try {
      const { password } = req.body;
      await User.updateOne({ _id: req.access_decoded.id }, { password });

      tokenBlacklist.add(req.access_token);

      res.status(200).json({ message: "密码修改成功" });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }
);

// 搜索用户
router.get(
  "/search",
  validateParams(["keyword"]),
  verifyAccessToken,
  async (req, res, next) => {
    try {
      const { keyword } = req.query;
      const users = await User.find({
        $or: [
          { account: { $regex: keyword, $options: "i" } },
          { "profile.nickname": { $regex: keyword, $options: "i" } },
        ],
      }).select("_id account role profile");

      res.status(200).json({ message: "搜索成功", users });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }
);

// 刷新 token
router.get("/refresh-token", verifyRefreshToken, async (req, res, next) => {
  try {
    const access_token = generateToken({
      tokenType: "ACCESS",
      id: req.refresh_decoded.id,
      boundIP: req.ip,
    });

    res.status(200).json({ message: "刷新成功", access_token });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

module.exports = router;
