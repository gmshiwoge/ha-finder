# HA Finder

一个极简的 Flutter 桌面应用，通过 mDNS/DNS-SD 搜索局域网中的 Home Assistant
服务器，并支持使用默认浏览器打开或复制服务器地址。

## 运行

```bash
flutter pub get
flutter run -d macos
```

在 Windows 上运行：

```bash
flutter run -d windows
```

## 使用 GitHub 编译桌面版本

将项目推送到 GitHub 的 `main` 分支后，`Build Windows` 和 `Build macOS` 工作流
会自动运行。也可以进入仓库的 **Actions** 页面，选择相应工作流并点击
**Run workflow** 手动触发。完成后，在该次运行页面的 Artifacts 区域下载：

- `HA-Finder-Windows-x64`
- `HA-Finder-macOS`

Windows 工作流还会生成单文件安装器 `HA-Finder-Setup.exe`，并将它发布到 GitHub
Releases，用户可以直接下载 EXE。安装后的程序仍包含 Flutter 所需的 DLL 和 data
目录；安装器负责自动管理这些文件。

macOS 工作流使用 Developer ID 签名并提交 Apple 公证。首次配置仓库后，在项目目录
运行 `./scripts/configure_github_secrets.sh`，根据提示输入 `.p12` 密码和 App Store
Connect Issuer ID。密码输入时不会显示，也不会写入项目文件。

加强搜索会在 mDNS 之后探测电脑所在的私有 IPv4 `/24` 网段，并验证常见端口
`8123`、`80` 和 `443` 上的 Home Assistant API 特征。

应用搜索 `_home-assistant._tcp.local` 服务。macOS 首次运行时，请允许应用访问
本地网络；Windows 防火墙询问时，请允许其访问专用网络。
