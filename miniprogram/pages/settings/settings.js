// pages/settings/settings.js —— 账号管理：增 / 改 / 删 / 批量添加
const api = require("../../utils/api.js");

const PLATFORMS = [
  { value: "mihoyo", label: "米游社（原神/星铁/绝区零/崩3）" },
  { value: "kuro", label: "库街区（鸣潮）" },
  { value: "yanyun", label: "燕云十六声" },
];

// 每个平台需要填哪个字段
const CRED_FIELD = {
  mihoyo: { key: "cookie", hint: "米游社 Cookie" },
  kuro: { key: "token", hint: "库街区 token" },
  yanyun: { key: "token", hint: "燕云 access_token" },
};

Page({
  data: {
    platforms: PLATFORMS,
    accounts: [],
    editing: null, // 正在编辑/新增的草稿
    batchText: "",
    showBatch: false,
  },

  onShow() {
    this.refresh();
  },

  refresh() {
    api
      .list()
      .then((r) => this.setData({ accounts: r.accounts || [] }))
      .catch((e) => wx.showToast({ title: e.message, icon: "none" }));
  },

  // ---- 新增 / 编辑 ----
  onNew() {
    this.setData({
      editing: { id: "", platform: "mihoyo", label: "", credential: "", enabled: true },
    });
  },

  onEdit(e) {
    const id = e.currentTarget.dataset.id;
    const acc = this.data.accounts.find((a) => a.id === id);
    if (!acc) return;
    // 已存账号拿不到明文凭据（后端只返回 has_credential），编辑时留空表示"不改凭据"
    this.setData({
      editing: {
        id: acc.id,
        platform: acc.platform,
        label: acc.label,
        credential: "",
        enabled: acc.enabled,
        hasCredential: acc.has_credential,
      },
    });
  },

  onCancelEdit() {
    this.setData({ editing: null });
  },

  onPlatformChange(e) {
    const editing = this.data.editing;
    editing.platform = PLATFORMS[e.detail.value].value;
    this.setData({ editing });
  },

  onField(e) {
    const editing = this.data.editing;
    editing[e.currentTarget.dataset.field] = e.detail.value;
    this.setData({ editing });
  },

  onSave() {
    const ed = this.data.editing;
    if (!ed) return;
    const field = CRED_FIELD[ed.platform] || CRED_FIELD.mihoyo;
    const account = {
      id: ed.id || undefined,
      platform: ed.platform,
      label: ed.label || PLATFORMS.find((p) => p.value === ed.platform).label,
      enabled: ed.enabled,
    };
    // 只有填了新凭据才更新 credential；编辑时留空则不动原凭据
    if (ed.credential) {
      account.credential = { [field.key]: ed.credential.trim() };
    } else if (!ed.id) {
      wx.showToast({ title: `请填写${field.hint}`, icon: "none" });
      return;
    }

    const p = ed.id ? api.update(account) : api.add(account);
    p.then(() => {
      wx.showToast({ title: "已保存", icon: "success" });
      this.setData({ editing: null });
      this.refresh();
    }).catch((err) => wx.showToast({ title: err.message, icon: "none" }));
  },

  onDelete(e) {
    const id = e.currentTarget.dataset.id;
    wx.showModal({
      title: "确认删除",
      content: "删除后无法恢复",
      success: (res) => {
        if (!res.confirm) return;
        api.remove(id).then(() => {
          wx.showToast({ title: "已删除", icon: "success" });
          this.refresh();
        });
      },
    });
  },

  onToggle(e) {
    const id = e.currentTarget.dataset.id;
    const acc = this.data.accounts.find((a) => a.id === id);
    api
      .update({ id, platform: acc.platform, label: acc.label, enabled: !acc.enabled })
      .then(() => this.refresh());
  },

  // ---- 批量导入 ----
  onToggleBatch() {
    this.setData({ showBatch: !this.data.showBatch });
  },

  onBatchInput(e) {
    this.setData({ batchText: e.detail.value });
  },

  // 批量格式：每行  platform|备注|凭据
  onBatchImport() {
    const lines = (this.data.batchText || "")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (!lines.length) {
      wx.showToast({ title: "没有内容", icon: "none" });
      return;
    }
    const tasks = [];
    lines.forEach((line) => {
      const [platform, label, cred] = line.split("|");
      const pf = PLATFORMS.find((p) => p.value === (platform || "").trim());
      if (!pf || !cred) return;
      const key = (CRED_FIELD[pf.value] || CRED_FIELD.mihoyo).key;
      tasks.push(
        api.add({
          platform: pf.value,
          label: (label || pf.label).trim(),
          credential: { [key]: cred.trim() },
          enabled: true,
        })
      );
    });
    if (!tasks.length) {
      wx.showToast({ title: "格式不对，见说明", icon: "none" });
      return;
    }
    wx.showLoading({ title: "导入中" });
    Promise.all(tasks)
      .then(() => {
        wx.hideLoading();
        wx.showToast({ title: `导入 ${tasks.length} 个`, icon: "success" });
        this.setData({ batchText: "", showBatch: false });
        this.refresh();
      })
      .catch(() => {
        wx.hideLoading();
        wx.showToast({ title: "部分导入失败", icon: "none" });
        this.refresh();
      });
  },
});
