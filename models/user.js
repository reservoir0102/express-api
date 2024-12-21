const mongoose = require("mongoose");
const bcryptjs = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
    account: {
      type: String,
      unique: true,
      trim: true,
      minlength: 2,
      maxlength: 20,
      required: true,
    },

    password: {
      type: String,
      required: true,
    },

    // 用户角色身份
    role: {
      type: String,
      enum: ["super_admin", "admin", "member", "visitor"],
      default: "visitor",
    },

    // 账号状态
    status: {
      type: String,
      enum: ["active", "suspended"],
      default: "active",
    },

    // 最后登录时间
    lastActiveAt: {
      type: Date,
      default: Date.now,
    },

    // 用户个人信息
    profile: {
      email: {
        type: String,
        default: null,
        trim: true,
        lowercase: true,
        match: [
          /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
          "请输入有效的邮箱地址",
        ],
      },
      phone: {
        type: String,
        default: null,
        trim: true,
        match: [/^1[3-9]\d{9}$/, "请输入有效的手机号码"],
      },
      nickname: {
        type: String,
        default: null,
        trim: true,
        maxLength: 12,
      },
      bio: {
        type: String,
        default: null,
        maxLength: 200,
      },
      gender: {
        type: String,
        enum: ["male", "female", "other"],
        default: "other",
      },
      avatar: {
        type: String,
        default: null,
      },
    },

    // 密码重置令牌
    passwordResetToken: {
      type: String,
      default: null,
    },

    // 密码重置令牌过期时间
    passwordResetExpires: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  // 密码加密，只有密码被修改的时候才加密
  if (this.isModified("password")) {
    const salt = await bcryptjs.genSalt(10); // 生成盐值，增加密码复杂度

    this.password = await bcryptjs.hash(this.password, salt); // 使用盐值对密码进行哈希
  }

  // 若没有 nickname ，生成默认昵称
  if (!this.profile.nickname) {
    const role = {
      super_admin: "超级管理员",
      admin: "管理员",
      member: "成员",
      visitor: "游客",
    };
    const nicknameNumber = this._id.toString().slice(-5);

    this.profile.nickname = role[this.role]
      ? `${role[this.role]}-${nicknameNumber}`
      : `未知用户-${nicknameNumber}`;
  }

  // 若没有 avatar，生成默认头像
  if (!this.profile.avatar) {
    this.profile.avatar = `https://api.dicebear.com/7.x/pixel-art/svg?seed=${this.profile.nickname}&size=100`;
  }

  next();
});

// 验证密码
userSchema.methods.comparePassword = async function (candidatePassword) {
  const isMatch = await bcryptjs.compare(candidatePassword, this.password);
  return isMatch;
};

module.exports = mongoose.model("User", userSchema);
