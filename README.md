# AegisCabinet-Zero

AegisCabinet-Zero 是一个面向物联网安全教学的校园智能外卖柜攻防仿真系统。项目使用 Streamlit 构建 4×4 数字孪生柜，在同一界面中对照普通认证与零信任认证，并可观察攻击输入、协议字段、防护决策和审计轨迹。

> 本项目是纯软件教学仿真，不连接真实柜机。示例密码、Schnorr 群参数与攻击时延均用于课堂演示，不能直接用于生产环境。

## 功能

- Schnorr 零知识证明三步握手：终端生成承诺、挑战响应，服务端只验证公开资产，不接收明文取件码。
- 时间侧信道对照：演示普通逐位比较产生的时延泄漏，以及常量时间比较和零知识入口的防护效果。
- 历史报文重放实验：检查时间窗、随机数、摘要缓存及设备/格口绑定。
- 固件溢出载荷实验：模拟长度校验、Stack Canary、CRC 校验和攻击后的柜门自锁。
- 4×4 数字孪生格口：联动展示锁定、解锁与安全自锁状态。
- 可视化审计：记录时延采样、重放报文、固件 payload、风险指标和状态机轨迹。

## 快速开始

需要 Python 3.10 或更高版本。

```bash
python -m venv .venv
```

Windows：

```powershell
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

macOS / Linux：

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

浏览器打开 `http://localhost:8501`。Windows 用户也可以双击 `run_AegisCabinet-Zero.bat`，脚本会检查并安装缺失依赖后启动应用。

## 使用方式

1. 在左侧选择格口，使用界面显示的 6 位演示取件码进行正常取件。
2. 切换“启用零知识功能外卖柜”，比较普通柜与零知识柜的认证资产和响应行为。
3. 依次运行时间侧信道、历史报文重放和恶意溢出载荷实验。
4. 在透明对照实验轨迹、入侵检测审计台和请求状态机中查看完整判定依据。

## 项目结构

```text
.
├── app.py                         # 仿真系统、攻防逻辑与界面
├── requirements.txt              # Python 依赖
└── run_AegisCabinet-Zero.bat      # Windows 一键启动脚本
```

## 安全边界

- 教学群参数较小，仅用于展示 Schnorr 证明的数学闭环；真实系统应使用经过审计的密码库、成熟椭圆曲线和硬件密钥保护。
- 仿真中的 Stack Canary 与 CRC 展示的是防护流程，不等同于真实固件的内存安全实现或签名验证。
- 生产部署还需要 TLS、设备身份、密钥轮换、固件签名、安全启动、后端授权和可靠的审计存储。

课程报告、汇报 PPT、生成素材和本地 UI 参考仓库未包含在本仓库中。
