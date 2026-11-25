# V7 顺序操作块与脚本哈希链实测

日期：2026-11-16。Windows，release，32 字节/块，Pallas/Vesta。
样例沿用 `target/salted-check/`：原文 36 字节，新文 35 字节，4 个操作块（keep32、keep1、delete3、insert[49,50]）。使用同一公开 JSON 和私有盐。

| 指标 | V6 历史测量 | V7 本次测量 |
|---|---:|---:|
| 状态元素数 | 144 | 10 |
| 单步业务约束 | 21,867 | 22,711 |
| Nova primary 约束 | 50,476 | 34,092 |
| Nova secondary 约束 | 10,349 | 10,349 |
| primary 变量 | 50,650 | 34,033 |
| secondary 变量 | 10,331 | 10,331 |
| setup (s) | 2.406119 | 1.891468 |
| prove (s) | 11.645683 | 3.142886 |
| verify (s) | 0.390906 | 0.258936 |
| setup 峰值工作集 (MiB) | 259.406 | 164.078 |
| prove 峰值工作集 (MiB) | 336.398 | 230.898 |
| verify 峰值工作集 (MiB) | 126.504 | 79.516 |
| 证明文件 (bytes) | 15,058 | 10,772 |

V6 来自 `BENCHMARK_V6.md`，不是本次交替运行的受控对照；单次墙钟时间受系统负载影响，不据此宣称稳定加速倍数。约束数和状态长度的降低是确定的结构差异。业务约束增加 844，Nova primary 总约束减少 16,384（约 32.5%）。

V7 setup：参数 1.657648 s，压缩密钥 0.233820 s。
V7 prove：递归 0.519146 s，压缩 2.623741 s；额外自检 0.079737 s，不计入 prove。
验证结果 `verified: true`。峰值内存为整个命令进程的工作集峰值，不是函数独占内存。

## 单步业务约束拆分

| 部分 | 约束数 |
|---|---:|
| 原文哈希链 | 10,048 |
| 新文哈希链 | 10,048 |
| 脚本哈希链及打包 | 945 |
| 私有盐初始化 | 314 |
| 原文/新文/插入槽字节范围 | 864 |
| 三个游标的上界检查 | 219 |
| 其余类型、长度、启用、编辑相等与游标约束 | 273 |
| 总计 | 22,711 |

脚本链约占 4.16%。原文和新文逐字节哈希仍占主要部分。

## 复现

```powershell
cargo test --release
.\target\release\valis-nova-demo.exe constraints target/salted-check/public.json
.\target\release\valis-nova-demo.exe setup target/salted-check/public.json target/salted-check/v7-pk.bin target/salted-check/v7-vk.bin
.\target\release\valis-nova-demo.exe prove target/salted-check/old.bin target/salted-check/public.json target/salted-check/v7-pk.bin target/salted-check/v7-proof.bin target/salted-check/private.salt
.\target\release\valis-nova-demo.exe verify target/salted-check/public.json target/salted-check/v7-vk.bin target/salted-check/v7-proof.bin
```

8 个单元测试、2 个 CLI 测试通过。测试同时检查 1 块与 128 块时状态长度和单步业务约束数不变；这不表示不同块数可复用当前密钥（块数仍进入上界约束常量）。临时样例与密钥在忽略的 target 目录内。
