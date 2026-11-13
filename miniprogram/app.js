// app.js —— 初始化云开发（云函数运行在服务端，调用第三方游戏接口不受前端域名白名单限制）
App({
  onLaunch() {
    if (!wx.cloud) {
      console.error("请使用 2.2.3 以上的基础库以使用云能力");
    } else {
      wx.cloud.init({
        traceUser: true,
        // 替换为你的云开发环境 ID（云开发控制台获取）
        env: "your-cloud-env-id",
      });
    }
  },
  globalData: {},
});
