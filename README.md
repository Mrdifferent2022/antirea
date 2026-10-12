# shiplint

**Lint your shipped artifacts for information leaks that reverse-engineering tools exploit.**

构建产物里的每一份"便利"——sourcemap、Go 构建元数据、未剥离的符号——都是逆向工具的攻击面。shiplint 在发布前扫描你的产物，报告泄露了什么、证据在哪、怎么修。

```
$ shiplint scan dist/
[HIGH] app.js.map
  web/sourcemap-file — Source map with embedded sourcesContent ships full original source code
  evidence: app.js.map contains sourcesContent — original sources can be fully reconstructed
  fix: Do not deploy .map files to public targets. ...
```

## 用法

```bash
npx shiplint scan <path> [--format console|json] [--fail-on info|warn|high|critical]
```

- `--format json`：机器可读输出，供 CI 消费
- `--fail-on`：有任何 ≥ 该 severity 的发现时退出码为 1（默认 `high`），可直接做 CI 卡点

## 规则 ↔ 逆向利用面对照表

每条规则对应逆向工程工具（如 [REA](https://github.com/morluto/rea)）的一项实际能力：

| 规则 | 检测内容 | 对应利用面 |
|---|---|---|
| `web/sourcemap-file` | 产物中含 `.map` 文件（含内嵌 sourcesContent） | sourcemap 还原完整源码 |
| `web/sourcemap-url` | bundle 尾部 `sourceMappingURL` 引用（远程 URL 升级为 high） | 指引逆向工具拉取源码地图 |
| `go/buildinfo-leak` | Go 二进制内嵌模块路径、依赖、VCS 信息 | REA go 模块：构建元数据检查 |

路线图（M1/M2）：Electron asar 明文与完整性检测、ELF/PE/Mach-O 符号未剥离、SARIF 报告（GitHub Code Scanning）、配置文件与 baseline、GitHub Action 封装。

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
