# 运行时数据目录

程序首次运行会在此生成 `vault.json`（加密凭据）与 `master.key`（主密钥）。
这两个文件**永远不会**被提交到 GitHub（见 .gitignore）。
`settings.json` 是首页保存的定时签到时间（运行时生成，也不上传）。
`games.example.json` 是可选的游戏表覆盖示例。
