# antirea

**Lint your shipped artifacts for information leaks that reverse-engineering tools exploit.**

构建产物里的每一份"便利"——sourcemap、Go 构建元数据、未剥离的符号——都是逆向工具的攻击面。antirea 在发布前扫描你的产物，报告泄露了什么、证据在哪、怎么修。

```
$ antirea scan dist/
[HIGH] app.js.map
  web/sourcemap-file — Source map with embedded sourcesContent ships full original source code
  evidence: app.js.map contains sourcesContent — original sources can be fully reconstructed
  fix: Do not deploy .map files to public targets. ...
```

## 用法

```bash
npx antirea scan <path> [--format console|json|sarif] [--fail-on info|warn|high|critical]
                        [--ignore <pattern>]...
```

- `--format json` / `--format sarif`：机器可读输出；SARIF 2.1.0 可直接上传 GitHub Code Scanning
- `--fail-on`：有任何 ≥ 该 severity 的发现时退出码为 1（默认 `high`），可直接做 CI 卡点
- `--ignore`：排除文件名或 glob（`*` 匹配单段），可重复或逗号分隔；扫描根目录下的 `.antireaignore` 文件（gitignore 风格）自动生效——已知接受的泄露用它屏蔽

## 规则 ↔ 逆向利用面对照表

每条规则对应逆向工程工具（如 [REA](https://github.com/morluto/rea)）的一项实际能力。severity 按"实际交出了多少"分级：

| 规则 | 检测内容 | 分级逻辑 | 对应利用面 |
|---|---|---|---|
| `web/sourcemap-file` | 产物中含 `.map` 文件 | 含 sourcesContent=high；仅路径结构=warn | sourcemap 还原完整源码 |
| `web/sourcemap-url` | bundle 尾部 `sourceMappingURL` 引用 | inline data URL 含源码=critical；inline 无源码/远程 URL=high；相对路径=warn | 指引逆向工具拉取（或直接解码内嵌的）源码地图 |
| `go/buildinfo-leak` | Go 二进制内嵌模块路径、依赖、VCS 信息 | 含 VCS=high，否则=warn；锚点解析 modinfo 块，不全文正则 | REA `inspect-go-binary` 构建元数据检查 |
| `electron/plaintext-asar` | asar 归档明文可读（解析头部并列出文件树作证据） | high | REA/Electron 应用解包 |
| `electron/fuse-integrity` | Electron fuse 未开启 asar 完整性校验/限制加载 | high | asar 被替换篡改后仍被执行 |
| `bin/unstripped-symbols` | ELF 带 `.symtab`/`.debug_*`、PE 引用 PDB 路径 | 符号表=high；仅 debug 段=warn | Ghidra/IDA/Hopper 反编译直接获得符号 |

路线图（M2）：Mach-O 符号检测、配置文件与 baseline、GitHub Action 封装。

## 对抗验证（实测记录）

规则不是纸上谈兵——每一条都对真实逆向工具验证过。以下为本仓库实测：

**Web/sourcemap**：用 REA `analyze-javascript-application` 分析 `tests/fixtures/web`（一个带 `app.js.map` 的 webpack bundle）：

- REA 成功解析出 `source_map_reference → ../src/secret-logic.ts`（原始源文件路径）
- `app.js.map` 内嵌的 `sourcesContent` 包含**完整原始 TypeScript 源码**，一行命令即可提取
- antirea 对同一目录命中 `web/sourcemap-file`（HIGH）+ `web/sourcemap-url`（WARN）——两个泄露点全部提前报告

**Go 二进制**：用 `go build` 默认参数编译一个模块名为 `corp.example/internal/billing` 的演示程序：

| | REA `inspect-go-binary` 提取到 | antirea 报告 |
|---|---|---|
| 默认构建 | 模块路径、go1.23.4、10 项构建设置、`vcs.revision` 完整提交哈希 | HIGH，证据字段与 REA 提取结果逐项对应 |
| 按 remediation 加固后（`-trimpath -buildvcs=false -ldflags="-s -w"`） | VCS 信息消失，构建设置减少到 7 项 | 降级为 WARN（模块路径为 Go 固有），退出码 0 通过 CI 卡点 |

这就是 antirea 的闭环：**逆向工具能拿到什么，antirea 就在发布前报什么；按建议修复后，逆向工具的收获随之消失。**

## 设计原则

- **证据优先**：每条发现都带可核实的证据（偏移、片段、提取值），不是空泛警告
- **修复具体**：remediation 给出可执行的构建参数或流水线改动
- **规则公开无损**：防御力来自修掉泄露，不来自规则保密——因此天然适合开源

## 开发

```bash
npm install
npm test        # vitest
npm run build   # tsc -> dist/
node dist/cli.js scan tests/fixtures/web   # 本地端到端
```

## License

MIT
