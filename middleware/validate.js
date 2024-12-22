function validateParams(requiredParams) {
  return (req, res, next) => {
    const method = req.method.toLowerCase();
    const sourceObj = method === "get" ? req.query : req.body;

    // 检查必填参数
    const missingParams = requiredParams.filter((param) => {
      // 检查参数是否存在且不为空
      return (
        sourceObj[param] === undefined ||
        sourceObj[param] === null ||
        sourceObj[param] === ""
      );
    });

    // 如果有缺失参数，抛出错误
    if (missingParams.length > 0) {
      const errorMessage = `缺少必填参数: ${missingParams.join(", ")}`;
      return res.status(400).json({ message: errorMessage });
    }

    next();
  };
}

module.exports = { validateParams };
