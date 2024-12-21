const express = require("express");
const User = require("../models/user");
const {
  authenticateToken,
  generateToken,
  registerLimiter,
} = require("../middleware/auth");

const router = express.Router();

// 游客登录
router.post("/visitor-login", registerLimiter, async (req, res, next) => {
  try {
    const { account, password, nickname } = req.body;
    const user = await User.findOne({ account });
    let newUser;

    if (user) {
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

    const token = generateToken(newUser);
    res.status(200).json({
      message: "游客登录成功",
      token,
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
});

// 登录
router.post("/login", async (req, res, next) => {
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

    const token = generateToken(user);

    res.status(200).json({
      message: "登录成功",
      token,
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

// 注册
router.post("/register", registerLimiter, async (req, res, next) => {
  try {
    const { account, password, role = "member" } = req.body;
    const existingUser = await User.findOne({ account });

    if (existingUser) {
      throw new Error("账号已被注册");
    }

    const user = new User({ account, password, role });
    await user.save();

    const token = generateToken(user);

    res.status(200).json({ message: "注册成功", token });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// 修改个人信息
router.put("/profile", authenticateToken, async (req, res, next) => {
  try {
    const profile = req.body;
    const user = await User.findById(req.user._id);

    user.profile = { ...user.profile, ...profile };
    await user.save();

    res.status(200).json({ message: "账号信息修改成功" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// 修改密码
router.put("/password", authenticateToken, async (req, res, next) => {
  try {
    const { password } = req.body;
    await User.updateOne({ _id: req.user._id }, { password });

    res.status(200).json({ message: "密码修改成功" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// 搜索用户
router.get("/search", authenticateToken, async (req, res, next) => {
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
});

module.exports = router;
