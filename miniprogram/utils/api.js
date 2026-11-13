// utils/api.js —— 统一封装云函数调用（所有账号操作都走后端，凭据不落在前端逻辑里）
const call = (action, extra = {}) =>
  wx.cloud
    .callFunction({
      name: "checkin",
      data: { action, ...extra },
    })
    .then((res) => {
      const r = res.result || {};
      if (!r.ok) throw new Error(r.error || "请求失败");
      return r;
    });

module.exports = {
  // 账号
  list: () => call("list"),
  add: (account) => call("add", { account }),
  update: (account) => call("update", { account }),
  remove: (account_id) => call("remove", { account_id }),
  // 签到
  checkin: (account_id) => call("checkin", account_id ? { account_id } : {}),
};
