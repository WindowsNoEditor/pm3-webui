# PM3一键工具 webUI

一个给 Proxmark3 用的**本地网页操作面板**。它本身**不实现任何 RFID/NFC 功能**,
只是把官方命令行客户端 `pm3` 的常用命令做成网页上的按钮和表单,把执行结果实时显示出来——
本质上是 **Proxmark3 命令行的"图形化输入替代",目的是让交互更顺手**,少敲命令、少记参数。

界面为深色主题,纯 Python 标准库实现(无 Tkinter、无第三方依赖),在浏览器中打开。

---

## 这是什么 / 不是什么

- ✅ 是:一个跑在本机的小服务,把命令喂给 `pm3` 客户端,并把客户端输出流式显示在网页上。
- ❌ 不是:固件、不是 Proxmark3 客户端的二次开发、也不修改固件的任何逻辑。
- 所有实际能力(读卡、找密钥、dump、克隆、模拟、脚本攻击等)**全部来自下面的固件/客户端**,
  本工具只负责"替你输入命令、整理展示结果"。

> 一句话:**它是 Proxmark3 CLI 的网页前端,方便交互而已。**

---

## 固件来源

本工具配套使用的是 Proxmark3 的 **Iceman 固件 / 客户端**(社区主流分支):

- 项目地址:<https://github.com/RfidResearchGroup/proxmark3>
- 协议:GPL-3.0(归原作者与社区所有)
- 本仓库**不包含**该固件源码,请自行 clone 并按其文档编译;本工具通过其生成的
  `pm3` 脚本 / `proxmark3` 客户端来工作。

我使用时对应的版本:`RfidResearchGroup/proxmark3` `master` 分支,提交 `5ed48c6`(2026-06-19)。
其它相近版本通常也可用,只要 `pm3` 客户端能正常连接设备即可。

---

## 我实测可用的环境

下面是我本机能够顺利跑通这套(固件客户端 + 本工具)的环境,供参考:

| 项目 | 实测情况 |
|------|----------|
| 操作系统 | macOS 26 |
| 芯片 | M4 |
| Python | 系统自带 `python3` 3.9.6(无需额外安装,本工具只用标准库) |
| Proxmark3 客户端 | Iceman 分支,本地 `make` 编译通过 |
| 设备连接 | USB-CDC,串口 `/dev/tty.usbmodemiceman1` |
| 浏览器 | 系统默认浏览器即可 |

> 我只在上面的 macOS 环境实测过;Linux 原理相同(同样用 `pty`,应可正常工作),
> Windows 为实验性支持(见下方"平台支持")。

---

## 运行

前置条件:已按 Iceman 文档编译好客户端(存在可执行的 `pm3` / `proxmark3` / `proxmark3.exe`),并接好设备。

启动器(按系统选一个):

| 系统 | 启动方式 |
|------|----------|
| macOS | 双击 `macos_start.command`(首次被拦:右键 → 打开 → 再点"打开") |
| Linux | 终端执行 `./linux_start.sh` |
| Windows | 双击 `windows_start.bat` |

也可直接用终端:`python3 pm3_web.py`(Windows 用 `py -3 pm3_web.py`)。
启动后会自动打开 `http://127.0.0.1:<随机端口>/`(仅监听本机回环)。

### 连接前:在左上角指定 pm3 运行路径(重要)

页面**左上角第一个输入框**要填 **Proxmark3 客户端的可执行文件路径**,也就是你本地
proxmark3 项目里那个 `pm3` 启动脚本(或 `proxmark3` / Windows 的 `proxmark3.exe`)的完整路径。

> 例(我本机的路径):`/Users/windowsnoeditor/Desktop/proxmark3/pm3`
>
> - macOS / Linux:一般是 `<你的 proxmark3 目录>/pm3`
> - Windows:一般是 `<你的 proxmark3 目录>\client\proxmark3.exe`,并在"串口"里选 COM 口(如 `COM3`)

程序会尝试自动填入常见路径,但**如果你的 proxmark3 不在工具旁边,请手动改成你自己的实际路径**。
填好后再选串口(可点"扫描")、设保存目录,点"连接"即可。

---

## 平台支持

| 系统 | 后端 | 说明 |
|------|------|------|
| macOS / Linux | 伪终端 `pty` | 输出实时流式,体验最佳(**macOS 已实测**) |
| Windows | 管道 pipe | **实验性,我未实测**。无 stdlib 伪终端,输出按命令批次返回(长任务期间不实时滚动,完成后整段显示);客户端用 `proxmark3.exe`,需在页面选择 COM 口(如 `COM3`) |

> Windows 上若想要与 macOS/Linux 一致的实时体验,建议在 WSL2 里跑(等同 Linux 环境)。

---

## 功能概览

- **设备 / 识别**:`hw version/status/tune`、`auto`、`hf/lf search`、`hf 14a info`
- **MIFARE Classic**:🧠 智能获取密钥(自动判断 PRNG/静态随机数,自动选 nested / hardnested /
  staticnested / darkside)、`fchk`、`autopwn`、`dump`、`restore`
- **脚本攻击**:调用客户端内置 pyscripts(已挑选本机实测可加载运行的):`fm11rf08s_recovery`、
  `fm11rf08s_full -r`、`mf_backdoor_dump`、`ntag22x_suncmac_recovery`、`hf_mfu_uscuid`、`script list`
- **复制卡片**:读源卡 → 写新卡(Gen1a `cload` / Gen2 `restore`)
- **手机复制**:读卡 → PM3 模拟该卡 → 手机复制 UID → 验证 UID 吻合后写入数据(向导式)
- **魔术卡 / Ultralight / 低频**:`cload/csetuid/cwipe`、`hf mfu`、`lf em410x/t55xx/hid`
- **左下状态面板**:卡片信息、已恢复密钥(按扇区 KeyA/KeyB)、扇区数据(按块 16 字节,尾块高亮)、任务执行情况
- **右侧控制台**:`pm3` 输出实时流式显示,并可手动输入任意命令

---

## 安全与法律

仅可用于**你本人拥有或已获得明确授权**的卡片进行测试与研究。请遵守当地法律法规,
不要用于复制/伪造他人或未授权的卡片。使用本工具产生的一切后果由使用者自行承担。

本工具按"原样"提供,不附带任何担保。

---

## 许可证

本项目采用 **GNU General Public License v3.0 (GPL-3.0)**,完整条款见 [LICENSE](LICENSE)。

- 你可以自由使用、修改、再分发本工具;但**分发修改版时必须同样以 GPL-3.0 开源**并保留版权声明。
- 本工具按"原样"提供,不含任何担保。
- 说明:本工具是独立进程的封装层,通过命令行/管道调用外部的 Proxmark3 客户端,
  **不包含也不链接** Proxmark3 源码;Proxmark3(同为 GPL-3.0)请按其仓库说明单独获取。
