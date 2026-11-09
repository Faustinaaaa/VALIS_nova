# Nova 私有原文编辑证明

使用 nova-snark 0.76.0（Pallas/Vesta + Spartan/IPA），将 Myers 差异拆成每块最多 8 个字节，再逐步证明编辑过程。原文作为私有 witness，新文和差异脚本作为公开输入。

## 分阶段运行

在本目录执行，命令形式与 VALIS_G16 对齐：

~~~powershell
cargo run --release -- diff examples/old.txt examples/new.txt public.json
cargo run --release -- setup public.json pk.bin vk.bin
cargo run --release -- prove examples/old.txt public.json pk.bin proof.bin
cargo test --release
~~~

- diff 读取两份文件的原始字节，生成公开语句。
- setup 只读取公开语句，将公共参数和压缩证明密钥打包保存；不需要原文。
- prove 是唯一需要私有原文的证明阶段，加载参数，不重新 setup。
- verify 只需要 public.json、可信的 vk.bin 和 proof.bin；不读取原文或 prover key。

public.json 的字段为 before_len、after、edits。after 与 Insert 使用 0–255 的整数数组，长度按字节计数。文件通过 fs::read 读取，支持非 UTF-8、NUL 和任意二进制内容，不做解码或换行转换。原文内容和路径不会保存到 public.json；与 G16 旧字符串格式不再直接兼容。

## 文件与参数复用

| 文件 | 内容 |
| --- | --- |
| public.json | 原文长度、公开目标文本、合并后的编辑操作 |
| pk.bin | 形状标识、Nova 公共参数 pp、压缩 prover key |
| vk.bin | 形状标识、压缩 verifier key |
| proof.bin | 形状标识、零知识 CompressedSNARK |

不保存 RecursiveSNARK、原文或未压缩 witness。输出可覆盖已有同名产物，但拒绝输出与输入路径相同。请使用独立的产物路径。

只要原文字节数、新文字节数、分块后的块数、BLOCK 和电路逻辑不变，可以复用 pk.bin/vk.bin，允许公开文本、操作类型和插入字节变化。形状不同会拒绝旧参数。本次改为字节编码并新增字节范围约束，必须重新 diff/setup/prove；旧字符版 JSON、密钥和证明不兼容。文件格式有版本与用途检查，文件头只用于防止误用，验证端仍须使用可信的 vk。

## 证明范围

证明某个私有原序列按公开脚本完整转换为公开目标文本。与当前 G16 一样，暂不加入原文承诺，因此不能绑定事先指定的原文件。仅改变删除区内容的另一原文也可能满足同一语句，这是声明本身允许的行为。

原文长度、目标文本和脚本公开；keep 部分能由目标文本与脚本推断，删除内容不进入公开状态。原文每步分配为私有 witness，公开状态只保存游标、原文长度、目标文本和脚本。游标单调推进，各原文位置最多消费一次；未使用承诺来证明不同步骤读取同一个外部原文件。

Myers 在电路外运行；证明不保证最短性或编辑权限。公开脚本绑定到按 8 字节分块后的编码；若不同 JSON 写法展开成相同块序列，则表示同一证明输入。电路通过 8 个布尔位重构约束，将私有原文字节（含删除部分）、公开新文字节和当前块插入槽位限制在 0..=255。

## 计时

所有阶段以秒输出。setup 包含公共参数和压缩密钥生成；prove 包含递归生成及压缩，递归自检单独输出；verify 只计最终压缩证明验证及完整消费检查。不包含文件读写、序列化和输入解析与尺寸检查。

## 代码结构

~~~text
src/
  main.rs              diff/setup/prove/verify 入口
  statement.rs         公开 JSON 编码与尺寸检查
  artifact.rs          保存和读取参数、证明文件
  myers.rs             差异算法和 Edit 类型
  circuit.rs           私有原文 witness、八字节主电路与公开状态
  gadgets.rs           字节范围、独热查找、条件相等和求和辅助约束
 tests/cli.rs           独立进程验证、参数复用及篡改测试
~~~

电路细节见 [FILE_DIFF.md](FILE_DIFF.md)。已有 1 KB 样例仍可用于上述四条命令；[旧基准](examples/BENCHMARK_1KB.md)是修改前原文公开版本的历史数据，不代表当前版本。

公开语句只做 JSON 字段/类型解析及输入尺寸溢出检查，不再提前比较 keep/insert 内容、判断脚本越界或检查完整消费。原文长度匹配由 set_source 保留为 witness 尺寸检查；编辑正确性由电路及验证端 completed 终态检查保证。空操作在分块时被忽略，空脚本仍生成 keep(0)。
