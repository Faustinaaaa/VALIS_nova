# Nova 私有原文编辑证明

使用 nova-snark 0.76.0（Pallas/Vesta + Spartan/IPA），将 Myers 差异拆成每块最多 32 个字节，再逐步证明编辑过程。每步只将当前块的最多 32 字节原文作为私有 witness，新文和差异脚本作为公开输入。

## 分阶段运行

在本目录执行，命令形式与 VALIS_G16 对齐：

~~~powershell
cargo run --release -- diff examples/old.txt examples/new.txt public.json
cargo run --release -- setup public.json pk.bin vk.bin
cargo run --release -- prove examples/old.txt public.json pk.bin proof.bin
cargo run --release -- verify public.json vk.bin proof.bin
cargo test --release
~~~

- diff 读取两份文件的原始字节，生成公开语句。
- setup 只读取公开语句，将公共参数和压缩证明密钥打包保存；不需要原文。
- prove 是唯一需要私有原文的证明阶段，加载参数，不重新 setup。
- verify 只需要 public.json、可信的 vk.bin 和 proof.bin；不读取原文或 prover key。

public.json 的字段为 before_len、before_commitment、after、edits。before_commitment 是 Poseidon 哈希链承诺，使用 64 位小写十六进制编码（域元素小端字节序）。after 与 Insert 使用 0–255 的整数数组，长度按字节计数。文件通过 fs::read 读取，支持非 UTF-8、NUL 和任意二进制内容，不做解码或换行转换。原文内容和路径不会保存到 public.json；与 G16 旧字符串格式不再直接兼容。

## 文件与参数复用

| 文件 | 内容 |
| --- | --- |
| public.json | 原文长度、Poseidon 原文承诺、公开目标文本、合并后的编辑操作 |
| pk.bin | 形状标识、Nova 公共参数 pp、压缩 prover key |
| vk.bin | 形状标识、压缩 verifier key |
| proof.bin | 形状标识、零知识 CompressedSNARK |

不保存 RecursiveSNARK、原文或未压缩 witness。输出可覆盖已有同名产物，但拒绝输出与输入路径相同。请使用独立的产物路径。

只要原文字节数、新文字节数、分块后的块数、BLOCK 和电路逻辑不变，可以复用 pk.bin/vk.bin，允许公开文本、操作类型和插入字节变化。形状不同会拒绝旧参数。本次增加 Poseidon 哈希链，必须重新 diff/setup/prove；旧无承诺 JSON、密钥和证明不兼容。承诺值改变但尺寸不变时可以复用新参数。文件格式有版本与用途检查，文件头只用于防止误用，验证端仍须使用可信的 vk。

## 证明范围

证明与公开承诺匹配的私有原序列按公开脚本完整转换为目标文本。验证者必须认可该承诺来自预期原文件；若允许证明者同时更换原文和承诺，就不能识别指定文件。

哈希链使用 Nova 内置 Poseidon sponge（U5，Standard，Simplex），每次吸收三个域元素：[域标记, 链状态, 字节或长度]，输出完整域元素。初始链为零；keep/delete 按顺序吸收原文字节，insert 和填充槽不更新。结束时使用另一个域标记绑定原文长度。最终承诺匹配属于 completed 的必要检查。

原文长度、承诺、新文和脚本公开；keep 内容可由新文推断。承诺没有随机盐，因此可猜测的原文可能被离线枚举。原文 witness 不导出。最终仅导出压缩证明，但最终递归状态中的链值应视为公开数据，不依赖它的保密性。

Myers 在电路外运行；证明不保证最短性或编辑权限。公开脚本绑定到按 32 字节分块后的编码；若不同 JSON 写法展开成相同块序列，则表示同一证明输入。电路通过 8 个布尔位重构约束，将私有原文字节（含删除部分）、公开新文字节和当前块插入槽位限制在 0..=255。

## 计时

所有阶段以秒输出。setup 包含公共参数和压缩密钥生成；prove 包含递归生成及压缩，递归自检单独输出；verify 只计最终压缩证明验证及完整消费检查。不包含文件读写、序列化和输入解析与尺寸检查。

## 代码结构

~~~text
src/
  main.rs              diff/setup/prove/verify 入口
  statement.rs         公开 JSON 编码与尺寸检查
  artifact.rs          保存和读取参数、证明文件
  myers.rs             差异算法和 Edit 类型
  circuit.rs           私有原文片段、32 字节主电路与公开状态
  hashchain.rs         Poseidon 原文承诺、条件链更新与编码
  gadgets.rs           字节范围、独热查找、条件相等和求和辅助约束
 tests/cli.rs           独立进程验证、参数复用及篡改测试
~~~

电路细节见 [FILE_DIFF.md](FILE_DIFF.md)。已有 1 KB 样例仍可用于上述四条命令；[旧基准](examples/BENCHMARK_1KB.md)是修改前原文公开版本的历史数据，不代表当前版本。

公开语句只做 JSON 字段/类型解析及输入尺寸溢出检查，不再提前比较 keep/insert 内容、判断脚本越界或检查完整消费。原文长度匹配由 set_source_step 保留为输入尺寸检查；编辑正确性由电路及验证端 completed 终态检查保证。空操作在分块时被忽略，空脚本仍生成 keep(0)。

每块容量现为 32 字节，操作行宽度为 34。原文片段优化前的所有参数（包括旧 32 字节版本）均不能复用，需重新 setup/prove；已有带承诺的 public.json 可以继续使用。

## 原文片段优化（V4）

每步只分配固定 32 个原文槽并检查范围，直接按槽位读取，删除了原文全文独热查找。main 每步通过 set_source_step 更新片段。原文哈希链保持不变，绑定各步消费片段的顺序和内容；新文和操作表仍完整保留。新增剩余长度的 64 位范围约束，保证每步不超过原文长度。

本次电路变化需要重新 setup/prove，V3 参数和证明被明确拒绝。已有 public.json 可以继续使用。old_len 仍绑定为电路常量并保留在 Shape 中，因此本次不开放跨原文长度的参数复用。

## 自动输出约束和内存统计

setup、prove 会输出 Nova 公共参数中的 primary/secondary R1CS 约束数和变量数。这是含递归包装的单步电路规模，不是纯 EditCircuit 业务约束数，也不是把约束数乘以步数后的值。verify 不加载 pp，因此不额外加载证明参数来统计约束。

所有命令结束时（包括普通错误返回）输出 Windows 当前工作集及进程生命周期峰值工作集，单位 MiB（1 MiB = 1,048,576 字节）。峰值包含文件加载、证明计算、序列化等，不是某个函数的内存增量，也不是峰值私有提交内存。每个命令独立运行，因而分别得到该命令的进程峰值；编译进程不计入。非 Windows 平台明确输出 unavailable。

这些统计不改变电路或产物格式，不需要因此重新 setup。
