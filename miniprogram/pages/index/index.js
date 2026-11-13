// pages/index/index.js —— 首页：批量签到
const api = require("../../utils/api.js");

Page({
  data: {
    accounts: [],
    results: [],
    loading: false,
    hasAccounts: false,
  },

  onShow() {
    this.refresh();
  },

  refresh() {
    api
      .list()
      .then((r) => {
        const accounts = r.accounts || [];
        this.setData({ accounts, hasAccounts: accounts.length > 0 });
      })
      .catch((e) => wx.showToast({ title: e.message, icon: "none" }));
  },

  // 一键签到全部
  onCheckinAll() {
    if (!this.data.hasAccounts) {
      wx.showToast({ title: "先去设置添加账号", icon: "none" });
      return;
    }
    this.setData({ loading: true, results: [] });
    api
      .checkin()
      .then((r) => {
        const results = r.results || [];
        this.setData({ results });
        const ok = results.filter((x) => x.success).length;
        wx.showToast({ title: `成功 ${ok}/${results.length}`, icon: "none" });
        this.refresh();
      })
      .catch((e) => wx.showToast({ title: e.message, icon: "none" }))
      .finally(() => this.setData({ loading: false }));
  },

  // 单账号签到
  onCheckinOne(e) {
    const id = e.currentTarget.dataset.id;
    wx.showLoading({ title: "签到中" });
    api
      .checkin(id)
      .then((r) => {
        const one = (r.results || [])[0];
        wx.hideLoading();
        if (one) {
          wx.showToast({
            title: one.success ? "签到成功" : one.message.slice(0, 20),
            icon: "none",
          });
        }
        this.refresh();
      })
      .catch((err) => {
        wx.hideLoading();
        wx.showToast({ title: err.message, icon: "none" });
      });
  },
});
