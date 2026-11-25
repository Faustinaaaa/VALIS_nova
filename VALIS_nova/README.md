> 当前为 V7：原文、新文和操作块都按步骤输入；操作表已改为脚本哈希链，递归状态固定 10 个元素。详细调用顺序和电路规则见 [SCRIPT_STREAM.md](SCRIPT_STREAM.md)，测试结果见 [BENCHMARK_V7.md](BENCHMARK_V7.md)。下文 V6 及更早的完整操作表描述为历史方案。V6 密钥需要重新 setup。

# Nova 私有原文编辑证明

使用 nova-snark 0.76.0（Pallas/Vesta + Spartan/IPA），将 Myers 差异拆成每块最多 32 个字节，再逐步证明编辑过程。每步只将当前块的最多 32 字节原文作为私有 witness，新文和差异脚本作为公开输入。

## 分阶段运行

在本目录执行，命令形式与 VALIS_G16 对齐：

~~~powershell
cargo run --release -- diff examples/old.txt examples/new.txt public.json private.salt
cargo run --release -- setup public.json pk.bin vk.bin
cargo run --release -- prove examples/old.txt public.json pk.bin proof.bin private.salt
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

只要原文字节数、新文字节数、分块后的块数、BLOCK 和电路逻辑不变，可以复用 pk.bin/vk.bin，允许公开文本、操作类型和插入字节变化。形状不同会拒绝旧参数。本次使用私有盐初始化 Poseidon 哈希链，必须重新 diff/setup/prove；旧无盐 JSON、密钥和证明不兼容。承诺值改变但尺寸不变时可以复用新参数。文件格式有版本与用途检查，文件头只用于防止误用，验证端仍须使用可信的 vk。

## 证明范围

证明与公开承诺匹配的私有原序列按公开脚本完整转换为目标文本。验证者必须认可该承诺来自预期原文件；若允许证明者同时更换原文和承诺，就不能识别指定文件。

哈希链使用 Nova 内置 Poseidon sponge（U5，Standard，Simplex），每次吸收三个域元素：[域标记, 链状态, 字节或长度]，输出完整域元素。公开初始状态的链槽为零，第一步在电路内用私有盐初始化链；keep/delete 按顺序吸收原文字节，insert 和填充槽不更新。结束时使用另一个域标记绑定原文长度。最终承诺匹配属于 completed 的必要检查。

原文长度、承诺、新文和脚本公开；keep 内容可由新文推断。承诺使用私有随机盐；盐泄露后，可猜测的原文仍可能被离线枚举。原文 witness 不导出。最终仅导出压缩证明，但最终递归状态中的链值应视为公开数据，不依赖它的保密性。

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

每块容量现为 32 字节，操作行宽度为 34。加盐前的所有参数（包括 V4 的 32 字节片段版本）均不能复用，需重新 diff/setup/prove。

## 原文片段优化（沿用 V4 的结构，当前格式为 V5）

每步只分配固定 32 个原文槽并检查范围，直接按槽位读取，删除了原文全文独热查找。main 每步通过 set_source_step 更新片段。原文哈希链保持不变，绑定各步消费片段的顺序和内容；新文仅保留承诺及链值，操作表仍完整保留。新增剩余长度的 64 位范围约束，保证每步不超过原文长度。

当前 V5 的带盐电路需要重新 diff/setup/prove，V4 及更早版本的参数和证明被明确拒绝。old_len 仍绑定为电路常量并保留在 Shape 中，因此本次不开放跨原文长度的参数复用。

## 自动输出约束和内存统计

setup、prove 会输出 Nova 公共参数中的 primary/secondary R1CS 约束数和变量数。这是含递归包装的单步电路规模，不是纯 EditCircuit 业务约束数，也不是把约束数乘以步数后的值。verify 不加载 pp，因此不额外加载证明参数来统计约束。

所有命令结束时（包括普通错误返回）输出 Windows 当前工作集及进程生命周期峰值工作集，单位 MiB（1 MiB = 1,048,576 字节）。峰值包含文件加载、证明计算、序列化等，不是某个函数的内存增量，也不是峰值私有提交内存。每个命令独立运行，因而分别得到该命令的进程峰值；编译进程不计入。非 Windows 平台明确输出 unavailable。

这些统计不改变电路或产物格式，不需要因此重新 setup。

## 私有随机盐（V5）

命令格式：

~~~text
diff <old.txt> <new.txt> <public.json> <private.salt>
setup <public.json> <pk.bin> <vk.bin>
prove <old.txt> <public.json> <pk.bin> <proof.bin> <private.salt>
verify <public.json> <vk.bin> <proof.bin>
~~~

盐是由 OsRng 系统随机源通过拒绝采样生成的域元素，保存为 64 位小写十六进制（小端域编码）。diff 若发现盐文件已存在，则读取并复用；文件不存在才新建。不同承诺需要新盐时使用新的盐文件路径。盐文件应与原文一起私下保留，不发给验证者；*.salt 已加入 .gitignore。移动或更换公开 JSON 名称不会改变盐文件内容，prove 仍需显式指定对应盐。

公开 z0 的末尾链槽仍为 0，但这个 0 只是首步占位。synthesize 分配私有盐，并利用操作行选择位 row_bits[0]，只在第一步把链初始化为 Poseidon(INIT_DOMAIN, 0, salt)。随后正常处理原文字节。其它步骤保持递归传入的链，不再次初始化。每步固定多生成一组候选 Poseidon 及选择约束，以保证形状不变。第一步即使是 insert 或 keep(0)，也会执行带盐初始化。

不公开 salt，也不公开 h₀ 作为初始输入，避免已知 h₀ 后可绕过盐枚举原文。最终输出链值本身已经带盐。后续步骤中的盐变量不影响计算，无需增加跨步盐相等约束，首步建立的链由 Nova 连续传递。

本次承诺算法和电路均改变，必须重新 diff/setup/prove，旧无盐 JSON 的承诺不能继续使用，V4 参数和证明也不能复用。相同尺寸下，改变盐的具体值仍可复用新的 V5 参数。


## V6：双侧片段输入（当前实现）

“流式新文”指电路每步只接收当前片段。CLI 仍将 public.json 的 after 数组读取到普通内存，没有改成磁盘文件的流式 JSON 解析。新文仍然公开，只是不再全文放进 Nova 状态。

每步固定分配原文、新文各 32 个字节槽。set_target_step(after, offset, edit) 装入新文片段，返回下一步偏移：keep 消费 n 字节，insert 消费插入长度，delete 不消费。未用槽填零，越界候选也填零后由电路上界检查拒绝。Nova::new 前装入首块，首次 prove_step 保留它，之后每步更换两侧片段。

状态布局为：

~~~text
z[0] = 原文游标
z[1] = 新文游标
z[2] = 操作游标
z[3] = 原文长度
z[4] = 新文目标承诺
z[5] = 新文动态哈希链
z[6 .. len-2] = 全部操作块
z[len-2] = 原文目标承诺
z[len-1] = 原文动态哈希链
~~~

状态长度现在为 8 + 34 × steps，与新文字节数无关。每一步直接比较两个片段的同一槽位，不再用新文全文选择器。keep 要求两侧字节相等；insert 要求新文字节等于公开操作中的插入字节。

新文链不需要盐，初始为 0，使用独立域标记：

~~~text
h_next = Poseidon(0x56414c495304, h, byte)
C_new = Poseidon(0x56414c495305, final_h, new_len)
~~~

keep/insert 的有效字节进入新文链，delete 和填充槽不更新。每步固定生成 32 组候选新文哈希；原文带盐哈希链保持不变。电路两侧都检查 consumed + remaining == 文件长度，remaining 限制为非负 64 位整数。

EditCircuit::statement 在电路外根据公开 after 计算 C_new，验证者也执行相同计算，不接受任意替换的新文承诺。completed 检查两侧完整消费、两条链分别匹配承诺、初始链为零及固定状态不变。变化的状态只有三个游标、z[5] 和最后一项。

操作表仍随块数增长；old_len/new_len 仍为电路常量及 Shape 参数，所以不同长度仍不能复用 setup。约束数不随新文长度增长，不等于约束内容完全相同。

V6 改变了电路与状态布局，旧 V5 密钥和证明不能复用，需重新 setup/prove。已有 V5 public.json 和 private.salt 可以继续使用，命令格式不变，无需重新 diff。

单步分类统计命令：

~~~powershell
cargo run --release -- constraints public.json
~~~

该命令按实际生成的约束路径分类，包含 source hashchain、target hashchain、salted initialization、字节范围、操作选择、keep/insert 和游标上界等。它只构造业务电路形状，不运行证明；其内存不代表 prove 内存。setup/prove 原有的 Nova R1CS 总计包含递归包装，与此业务计数不同。
