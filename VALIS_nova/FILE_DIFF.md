# 当前版本说明

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

---

以下为完整流程及历史演进说明，V4/V5 兼容性记录以开头 V6 说明为准。

# 文件差异证明：从 main 到单步电路

本文对应当前 VALIS_nova 代码，按 main 的执行顺序介绍每个阶段：谁调用谁、传入什么、得到什么，以及电路如何检查编辑操作。

当前使用 nova-snark 0.76.0，每个编辑块最多处理 **32 个字节**。每步只接收两侧各 32 字节的片段，操作表仍完整保留。当前已加入 Poseidon 原文哈希链，公开承诺绑定完整原文，包括删除内容。文件使用 fs::read 读取，所有长度和游标都按字节计数，不按 Unicode 字符计数。文件可以包含非 UTF-8 数据；中文字符也可能被拆到两个块里。

## 1. 从程序入口看整个流程

程序入口是 [src/main.rs](src/main.rs) 中的 main()。它读取命令行参数，根据命令进入一个分支。一次运行只执行一个分支。

~~~text
diff：   原文件 + 新文件 → Myers 编辑脚本 → public.json
setup：  public.json → 确定电路形状 → pk.bin + vk.bin
prove：  原文件 + public.json + pk.bin → proof.bin
verify： public.json + vk.bin + proof.bin → 接受或报错
~~~

在 VALIS_nova 目录下运行：

~~~powershell
cargo run --release -- diff examples/old.txt examples/new.txt public.json private.salt
cargo run --release -- setup public.json pk.bin vk.bin
cargo run --release -- prove examples/old.txt public.json pk.bin proof.bin private.salt
cargo run --release -- verify public.json vk.bin proof.bin
~~~

这些文件分别负责：

| 源码 | 工作 |
| --- | --- |
| main.rs | 命令分派、读取输入、调用证明库、输出时间 |
| myers.rs | 定义 Edit，计算字节序列的差异 |
| statement.rs | 定义公开 JSON，将公开内容转成电路输入 |
| circuit.rs | 拆块、编码状态、装入原文、定义单步约束、检查终态 |
| hashchain.rs | Poseidon 承诺、条件哈希链更新和域元素编码 |
| gadgets.rs | 求和、选择、字节范围和条件相等等约束组件 |
| artifact.rs | 参数与证明的保存、加载、形状检查、路径检查 |

diff 只是准备输入的工具，不在证明电路里。证明者也可以自行准备符合格式的 JSON。电路证明编辑操作正确，不证明脚本一定由 Myers 生成，也不证明编辑次数最少。

## 2. 贯穿全文的例子

假设两个文件没有末尾换行，内容为：

~~~text
原文件：abcdefghijXYZ
新文件：abcdefghij12
~~~

原文 13 字节，新文 12 字节。一个对应的编辑脚本是：

~~~text
keep(10), delete(3), insert([49, 50])
~~~

49、50 是字符 1、2 的字节值。keep 消费原文并保留到新文；delete 只消费原文；insert 将指定字节加入新文。

拆块后：

~~~text
第 0 块：keep(10)
第 1 块：delete(3)
第 2 块：insert([49, 50])
~~~

这里有 3 条原始操作、3 个块，因此要证明 3 个 step。代码中的 steps 指分块后的块数。

## 3. diff：从两个文件生成公开 JSON

### 3.1 main 中的调用顺序

~~~text
main 的 diff 分支
  → distinct_paths([原文件路径, JSON 输出路径])
  → distinct_paths([新文件路径, JSON 输出路径])
  → fs::read(原文件路径) → before
  → fs::read(新文件路径) → after
  → myers_diff(&before, &after) → edits
  → 打印每条 edit
  → 从指定的 private.salt 读取已有盐，或由系统随机源生成并保存新盐
  → hashchain::commitment(&before, salt) → 承诺域元素
  → hashchain::encode(承诺) → 十六进制字符串
  → 构造 Statement { before_len, before_commitment, after, edits }
  → public.circuit()
  → serde_json::to_vec_pretty(&public) → JSON 字节
  → fs::write(JSON 输出路径, JSON 字节)
~~~

distinct_paths 防止 JSON 输出覆盖输入。两个输入可以是同一个文件。fs::read 的输入是路径，输出是 Vec<u8>，即原始字节数组。

### 3.2 myers_diff 的输入、计算和输出

函数位于 [src/myers.rs](src/myers.rs)：

~~~rust
pub fn myers_diff(old: &[u8], new: &[u8]) -> Vec<Edit>
~~~

输入两份字节序列，输出操作数组。Edit 是枚举：

~~~rust
pub enum Edit {
    Keep(usize),
    Delete(usize),
    Insert(Vec<u8>),
}
~~~

函数内部可以分成四步：

1. 处理空文件：原文为空就插入新文，新文为空就删除原文，两者都为空就返回空脚本。
2. 从少到多尝试插入和删除的次数；遇到相同字节时继续向前匹配。
3. 找到到达两个文件末尾的路径，再回溯出具体操作。
4. 反转回溯结果，并合并相邻同类操作。例如三个 Keep(1) 合成 Keep(3)。

这些全部是电路外的普通计算。Edit 的 fmt 方法只负责打印格式，例如 keep(10)、insert([49, 50])，不参与证明。

### 3.3 Statement 保存什么

结构体位于 [src/statement.rs](src/statement.rs)：

~~~rust
pub(crate) struct Statement {
    pub before_len: usize,
    pub before_commitment: String,
    pub after: Vec<u8>,
    pub edits: Vec<Edit>,
}
~~~

这四个字段全部公开：原文长度、原文承诺、新文全部字节、未分块的脚本。原文内容不在其中。

例子的 JSON 可以写成：

~~~json
{
  "before_len": 13,
  "before_commitment": "<由 diff 计算的 64 位小写十六进制承诺>",
  "after": [97,98,99,100,101,102,103,104,105,106,49,50],
  "edits": [
    {"Keep": 10},
    {"Delete": 3},
    {"Insert": [49,50]}
  ]
}
~~~

上面承诺位置是说明用占位符，实际运行必须使用 diff 计算出的规范值，不能直接复制占位符。

当前没有 version 字段；after 和 Insert 是整数数组，不是字符串。

写出 JSON 前，main 调用 public.circuit() 检查编码尺寸并构造一次电路输入，但丢弃它的返回值。保存的 JSON 仍是未分块脚本，不是分块后的操作表。

## 4. 各阶段共用的准备：JSON 如何变成电路输入

setup、prove、verify 都会先读取 JSON，再调用 public.circuit()。这部分发生在电路外。

### 4.1 read_statement(path)

调用关系：

~~~text
read_statement(path)
  → fs::read(path)
  → serde_json::from_slice(JSON 字节)
  → Statement
~~~

输入是 JSON 路径，输出是 Statement，失败返回错误。Serde 负责字段和类型解析：字节必须能表示为 u8，未知字段会被拒绝。

### 4.2 Statement::circuit(&self)

函数签名：

~~~rust
pub fn circuit(&self) -> Result<(EditCircuit, Vec<F>), String>
~~~

输入是当前 Statement，输出两个对象：

| 输出 | 含义 |
| --- | --- |
| EditCircuit | 保存电路尺寸，以及私有原文 witness 的存储位置 |
| Vec<F> | 初始公开状态，通常命名为 z0 |

F 是电路使用的有限域类型，可以先理解成电路使用的数字类型。当前每个字节对应一个 F，不是把 8 字节打包成一个数。

内部依次执行：

~~~text
统计拆块数量，并检查整数溢出
  → 计算状态长度，检查尺寸和分配大小是否溢出（私有片段固定为 BLOCK 个元素）
  → chunks(&self.edits) → tape
  → hashchain::decode(&self.before_commitment) → commitment
  → EditCircuit::statement(self.before_len, &self.after, &tape, commitment)
  → 返回 (circuit, z0)
~~~

这些检查避免大小计算出错，不保证机器一定有足够内存。

这里不预先比较 keep 字节、不判断 insert 内容是否匹配、不判断脚本越界、不检查完整消费。编辑正确性由电路和最终 completed 检查负责。

### 4.3 chunks(edits)：每块最多 32 字节

~~~rust
pub(crate) fn chunks(edits: &[Edit]) -> Vec<Edit>
~~~

输入未分块脚本，输出分块脚本，仍使用 Edit 类型。

Keep(65) 拆成 Keep(32)、Keep(32)、Keep(1)。Delete 同理。Insert 使用字节切片的 chunks(32) 拆分。

每块只包含一种操作，不会把 keep(2) 和 delete(3) 合在一块。长度为零的操作不产生块；如果结果完全为空，就添加 Keep(0)，使 Nova 至少执行一步。Keep(0) 不消费文本，但操作游标仍然加一。如果原文或新文非空，单靠这个空步骤无法通过最终完整性检查。

**chunks 只拆分操作，不给原文或新文补零。**

### 4.4 EditCircuit::statement：建立对象和状态

~~~rust
pub(crate) fn statement(
    old_len: usize,
    new: &[u8],
    tape: &[Edit],
    commitment: F,
) -> (Self, Vec<F>)
~~~

输入依次是原文字节数、新文字节、已经拆好的块、公开承诺。函数先建立对象：

~~~text
EditCircuit {
    old_len = 原文字节数,
    new_len = 新文字节数,
    steps   = 块数,
    source_block = 32 个零组成的本步原文片段
}
~~~

source_block 暂时全零。setup 只需要形状，verify 不需要原文；prove 每步装入对应片段，不在电路对象中保存整份原文。

然后建立初始状态：

~~~text
z0 = [0, 0, 0, 原文长度, 新文承诺, 新文链初始值 0, 全部操作块的编码..., 目标承诺 C, 当前链状态 h=0]
      ↑  ↑  ↑
      原文游标、新文游标、操作游标
~~~

每块固定编码为 34 个数：

~~~text
[操作类型, 有效长度, 数据0, 数据1, ..., 数据31]
~~~

操作类型是 0=keep、1=delete、2=insert。例如：

~~~text
keep(2)         → [0, 2, 0 × 32]
delete(3)       → [1, 3, 0 × 32]
insert([49,50]) → [2, 2, 49, 50, 0 × 30]
~~~

上述 0 × n 表示连续 n 个零，仅为简写。

keep/delete 不使用插入数据槽，因此全部填零。insert 写入有效字节，剩余槽填零。

**填充零不代表真实文本中的零字节。** 长度决定槽是否生效。例如 Insert([0]) 的有效长度是 1，第一槽是真实数据；长度以外的零只是占位。

scalar(n) 是编码时的小工具，输入 usize 整数，输出对应的 F。

例子中 z0 长度是 8 + 34 × 3 = 110。整张操作表都在里面，后续每一步根据操作游标选择一行。

### 4.5 原文长度为什么放在 z[3]

z[3] 明确携带公开原文长度，电路约束它等于 self.old_len。

不过当前 old_len 本身已经决定电路形状，completed 也直接使用 self.old_len，所以这个状态字段有一定冗余。这里描述的是当前仍保留它的实现。长度不是原文承诺，不能识别具体是哪份原文件。

## 5. setup：建立可复用参数

### 5.1 main 中的调用顺序

~~~text
main 的 setup 分支
  → distinct_paths([public.json, pk.bin, vk.bin])
  → read_statement(public.json) → public
  → public.circuit() → (circuit, z0)，此处丢弃 z0
  → Shape::from(&circuit) → shape
  → PP::setup(&circuit, &*S1::ck_floor(), &*S2::ck_floor()) → pp
  → Proof::setup(&pp) → (pk, vk)
  → save(pk.bin, "prover", &shape, &(pp, pk))
  → save(vk.bin, "verifier", &shape, &vk)
~~~

### 5.2 main 里的类型简称

| 名称 | 含义 |
| --- | --- |
| E1、E2 | Pallas/Vesta 两个曲线引擎 |
| S1、S2 | 两侧使用的 Spartan RelaxedR1CSSNARK，搭配 IPA EvaluationEngine |
| PP | PublicParams，Nova 公共参数 |
| PK、VK | 压缩证明所用的证明密钥和验证密钥 |
| Proof | CompressedSNARK，最终压缩证明的类型 |

### 5.3 Shape::from(&circuit)

输入电路对象，输出形状描述。例如：

~~~text
{ block: 32, old_len: 13, new_len: 12, steps: 3 }
~~~

它只记录尺寸，不保存具体新文、原文或操作内容，也不是公开 JSON 的哈希。

### 5.4 PP::setup 和 Proof::setup

PP::setup 输入电路对象和后端的承诺密钥尺寸提示，输出 pp。S1::ck_floor() 和 S2::ck_floor() 提供库所需的尺寸提示，不是编辑数据。

Nova 通过 arity、synthesize 等接口获得电路形状。synthesize 的业务逻辑在第 7 节详细解释。

setup 不读取真实原文件，source_block 中的零值用于准备形状。它不是在证明全零原文满足此次编辑，也不要求某个具体 witness 在 setup 时就通过编辑验证。

Proof::setup 输入 pp，输出压缩证明使用的 pk、vk。save 将它们写出：

| 文件 | 保存的主要对象 |
| --- | --- |
| pk.bin | (pp, pk) |
| vk.bin | vk |

二进制文件还带有格式标记、类型和 Shape。

setup 从 public.json 取得形状，不把新文内容或操作内容写死。满足相同形状的其他公开输入可以复用参数。

## 6. prove 前半段：装入原文并开始逐步证明

调用顺序：

~~~text
main 的 prove 分支
  → distinct_paths([原文件, public.json, pk.bin, proof.bin])
  → fs::read(原文件) → before
  → read_statement(public.json) → public
  → public.circuit() → (circuit, z0)
  → 读取 private.salt，decode 后调用 circuit.set_salt(salt)
  → chunks(&public.edits) → tape
  → circuit.set_source_step(&before, 0, &tape[0]) → source_offset
  → circuit.set_target_step(&public.after, 0, &tape[0]) → target_offset
  → Shape::from(&circuit) → shape
  → load(pk.bin, "prover", &shape) → (pp, pk)
  → RecursiveSNARK::new(&pp, &circuit, &z0) → recursive
  → 循环 steps 次：第 0 次保留首块，其余先 set_source_step 和 set_target_step 装入两侧片段
  → recursive.prove_step(&pp, &circuit)
~~~

### 6.1 set_source_step：装入本步原文片段

~~~rust
set_source_step(&mut self, before: &[u8], offset: usize, edit: &Edit)
    -> Result<usize, String>
~~~

prove 先从私有盐文件读取规范域元素并调用 set_salt。随后输入完整原文的借用、原文偏移和当前编辑块。完整原文只存在 main 的普通内存里，不进入每步电路。

keep/delete 从 offset 开始最多取 32 字节放进 source_block，剩余槽填零；insert 不取原文，全部填零。返回下一步原文偏移。它只准备 witness，不比较 keep/insert 内容或原文承诺。

函数检查原文尺寸和块容量；如果脚本要求的字节超出原文，缺失处填零，之后由电路的原文消费上界约束拒绝。整数偏移计算溢出直接报错。

初始化 RecursiveSNARK::new 之前必须装入第 0 块。库的第一次 prove_step 只登记初始化时已执行的第一步，不再换片段；从第二次开始，每次调用前装入下一块。

### 6.2 RecursiveSNARK::new 和 prove_step

RecursiveSNARK::new 输入 pp、电路对象、z0，输出内存中的递归证明对象。初始化过程会准备第一步相关计算。

随后按库的接口约定调用 prove_step 共 steps 次，完成总共 steps 个业务步骤，并不是多处理一个块。prove_step 输入 pp 和 circuit，更新 recursive，返回成功或错误，不生成单独的块证明文件。

每次传入同一形状的 circuit，但 source_block 已替换为当前步骤需要的片段。本步选哪个块，由递归状态的操作游标决定。Nova 将上一步输出连接到下一步输入，电路定义每一步如何变化。

下面进入这一步实际使用的约束。

## 7. 电路入口：EditCircuit::synthesize

EditCircuit 实现 StepCircuit<F>。StepCircuit 是 Nova 要求的单步电路接口，EditCircuit 是本项目的实现。

~~~rust
fn arity(&self) -> usize
// 返回 8 + 34 * steps

fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[Num],
) -> Result<Vec<Num>, SynthesisError>
~~~

输入和输出：

| 项目 | 含义 |
| --- | --- |
| self | 固定尺寸及私有原文片段 source_block |
| cs | 收集变量和约束的容器，可以理解为记录计算规则的本子 |
| z | 当前步骤的状态；Num 是电路中已经分配的数字变量 |
| 返回值 next | 下一步状态 |
| 对 cs 的影响 | 增加本步所需的变量和约束 |

synthesize 不直接输出一个证明。它描述计算规则，Nova 再使用这些规则生成证明。

Num::alloc 提供一个候选赋值；cs.enforce、Num::mul 等写出的约束才保证赋值符合规则。不能只依赖普通 Rust 代码算对了结果。

### 7.1 分配当前原文片段

遍历 self.source_block，用 Num::alloc 固定分配 32 个私有变量，再逐个调用 enforce_byte。即使原文有几千字节，每步也只分配这 32 个原文字节变量。

未消费的槽也检查字节范围，但不参与 keep 比较或哈希链更新。CLI 将填充槽写为零；正确性不依赖这些无用槽一定为零。

### 7.2 分配新文片段

用 Num::alloc 分配 target_block 的 32 个字节，并逐个 enforce_byte。完整新文不在状态中；状态布局见本文开头 V6 说明。操作表从 z[6] 开始，新文目标承诺在 z[4]，动态链在 z[5]。

### 7.3 根据操作游标选出当前行

先调用 sum(cs, 空数组, 1)，得到被约束为 1 的变量 one。

然后：

~~~text
selectors(cs, index=z[2], enabled=one, count=steps) → row_bits
~~~

例如 4 个块、操作游标为 2 时，row_bits 必须是 [0,0,1,0]。“独热”就是恰好一个位置是 1，其他位置是 0。

对操作表的 34 列分别调用 select：

~~~text
取出该列的所有行 → entries
select(cs, row_bits, entries) → 当前行的这一列
~~~

选择行后还分配私有 salt，调用 initialize_if(cs, chain, salt, row_bits[0])：第一步先初始化带盐链，其它步骤不改变已有链。

得到 row，其中包含操作类型、有效长度和 32 个数据槽。34 列共用同一组 row_bits，因此不能从不同操作行拼接字段。

随后对选出的 32 个数据槽全部执行 enforce_byte，包括填充槽。电路外编码会将无用槽设为零；电路本身没有再单独要求所有无用槽必须为零，而是根据有效长度停用它们。

### 7.4 检查类型、长度，决定读取哪边

~~~text
selectors(cs, row[0], one, 3) → kinds
selectors(cs, row[1], one, 33) → lengths
~~~

kinds 分别表示 keep、delete、insert，必须恰好一个为 1，因此类型只能为 0、1、2。

lengths 分别表示长度 0 到 32，必须恰好一个为 1，因此有效长度只能为 0 到 32。长度 2 对应 [0,0,1,0,...,0]（共 33 项）。

通过 sum 计算：

~~~text
reads_old = kinds[0] + kinds[1]   // keep 或 delete
reads_new = kinds[0] + kinds[2]   // keep 或 insert
~~~

keep 读取两边，delete 只读取原文，insert 只读取新文。

### 7.5 固定处理 32 个槽位

代码始终执行 for slot in 0..BLOCK。即使有效长度为 2，也生成全部 32 个槽的约束。

每个槽依次执行下面六步。

**第一步：计算是否生效。**

~~~text
active = sum(lengths[slot+1 ..])
~~~

含义是“有效长度是否大于槽位编号”。长度 2 时，32 个 active 中前两个为 1，其余 30 个为 0。

**第二步：计算是否需要读取两边。**

~~~text
old_enabled = active × reads_old
new_enabled = active × reads_new
~~~

通过 Num::mul 添加乘法约束。无效槽两边都不读，delete 的有效槽只读原文，insert 的有效槽只读新文。

**第三、四步：直接读取片段槽位。**

old_char = old[slot]，new_char = new[slot]。两侧均不再生成全文查找选择器。消费上界由游标约束保证，片段内容和顺序由哈希链绑定。

**第五步：检查对应的编辑关系。**

~~~text
keep_enabled   = active × kinds[0]
insert_enabled = active × kinds[2]

equal_if(cs, keep_enabled, old_char, new_char)
equal_if(cs, insert_enabled, new_char, row[2+slot])
~~~

keep 生效时要求原文字节等于新文字节。insert 生效时要求新文字节等于公开脚本里的插入字节。

delete 没有字节相等检查，只需要消费片段字节、累计哈希链，并满足原文长度上界。

**第六步：更新原文哈希链。**

调用 hashchain::absorb_if(cs, &chain, &old_char, &old_enabled)，返回新的链状态。内部固定生成 Poseidon 候选哈希，再约束：

~~~text
candidate = Poseidon(BYTE_DOMAIN, chain, old_char)
next_chain = chain + old_enabled × (candidate - chain)
~~~

keep/delete 的有效槽会更新链，insert 和填充槽保留原值。每步固定生成 32 组哈希约束，操作类型改变不影响形状。

### 7.6 更新游标，输出 next

处理完 32 个槽后：

~~~text
next[0] = z[0] + 所有 old_enabled 之和
next[1] = z[1] + 所有 new_enabled 之和
next[2] = z[2] + 1
next[3..5] = z[3..5]
next[5] = 本步新文链
next[6 .. len-1] = z[6 .. len-1]
next[len-1] = 本步处理后的哈希链状态
~~~

原文游标更新后还调用 enforce_source_bound，要求已消费长度加上非负剩余长度等于 old_len，防止越界。

前三项用 sum 约束，末尾链值使用本步哈希输出，其余部分直接复用输入变量。所以原文长度、新文、操作表和目标承诺在步骤之间保持不变，末尾的哈希链状态则随原文消费更新。

| 操作 | 原文游标 | 新文游标 | 操作游标 |
| --- | --- | --- | --- |
| keep(n) | +n | +n | +1 |
| delete(n) | +n | 不变 | +1 |
| insert(n 字节) | 不变 | +n | +1 |

贯穿示例的变化：

| 状态 | 原文游标 | 新文游标 | 操作游标 |
| --- | --- | --- | --- |
| 初始 | 0 | 0 | 0 |
| keep(10) 后 | 10 | 10 | 1 |
| delete(3) 后 | 13 | 10 | 2 |
| insert([49,50]) 后 | 13 | 12 | 3 |

## 8. gadgets.rs 中每个辅助函数的输入和输出

这些函数被 synthesize 直接或间接调用。cs.namespace 只是给约束分组命名，方便定位问题，不是额外的公开输入。

### 8.1 value(n)

输入 &Num，输出它的候选赋值 F。缺少赋值就返回错误。其他组件通过它计算候选结果，它本身不生成约束。

### 8.2 enforce_byte(cs, byte)

输入一个变量，输出 Result<()>。实际效果是在 cs 中加入 8 个布尔位及重构约束：

~~~text
每个位：bit × (bit - 1) = 0
byte = bit0 + 2×bit1 + 4×bit2 + ... + 128×bit7
~~~

第一条要求位只能为 0 或 1，第二条保证 byte 只能在 0 到 255。

### 8.3 sum(cs, terms, constant)

输入变量数组和整数常数，输出新变量 out：

~~~text
(constant + 所有 terms 的和) × 1 = out
~~~

内部先用 value 算候选和，再用 cs.enforce 写入约束。它用于游标加法、启用标志计算和查找结果求和。

### 8.4 selectors(cs, index, enabled, count)

输入索引、启用标志、可选位置数，输出 count 个选择位。

调用方必须保证 enabled 是 0 或 1。本电路通过常量、独热结果和布尔标志乘积满足这个要求。

内部添加：

~~~text
每个 bits[i] 都是 0 或 1
sum(bits) = enabled
enabled × index = sum(i × bits[i])
~~~

enabled=1 时恰好选择一个位置，而且位置编号等于 index；enabled=0 时全部为零，不限制 index。

count=0 时只能停用，因此不能从空文本读取字节。这个组件同时承担索引绑定和启用时的范围检查。

### 8.5 select(cs, bits, entries)

输入等长的选择位数组和数据数组，输出：

~~~text
out = sum(bits[i] × entries[i])
~~~

内部调用 Num::mul 得到乘积，再调用 sum。它不重复检查独热性质，调用方需要先通过 selectors 等规则约束 bits。

例如 [0,1,0] 选择 [97,98,99] 得到 98；全零选择位得到 0。

当前实现需要遍历整张表，不等同于普通程序中直接访问 entries[index] 的常数时间读取。

### 8.6 equal_if(cs, enabled, a, b)

输入启用标志和两个变量，没有新变量返回，只添加：

~~~text
enabled × (a - b) = 0
~~~

启用时强制 a=b，停用时这条规则不限制二者是否相等。调用方负责 enabled 的布尔性。

## 9. 回到 prove：自检、压缩和保存

步骤循环结束后，main 继续执行：

~~~text
recursive.verify(&pp, circuit.steps, &z0) → output
  → circuit.completed(&z0, &output) → bool
  → Proof::prove(&pp, &pk, &recursive) → proof
  → save(proof.bin, "proof", &shape, &proof)
~~~

### 9.1 recursive.verify

输入公共参数、步数、初始状态，验证内存里的递归证明，并返回最终状态 output。失败直接返回错误。

### 9.2 completed(initial, output)

输入初始状态和最终状态，输出 bool。它依次检查：

~~~text
initial.len() == arity()
output.len() == initial.len()
output[0] == old_len
output[1] == new_len
output[2] == steps
initial 的末尾链状态 == 0
initial[5] == 0
output[3..5] == initial[3..5]
output[6 .. len-1] == initial[6 .. len-1]
target_finish(output[5], new_len) == initial[4]
hashchain::finish(output[len-1], old_len) == initial[len-2]
~~~

也就是原文、新文、脚本都完整消费，固定公开数据没有变化，并且最终哈希链与公开原文承诺匹配。

**completed 在电路外执行，但属于完整验证流程。** 单步约束保证每步合法，completed 保证没有只处理一个合法前缀就结束。不能只调用库的 verify 而省略业务终态检查。

### 9.3 Proof::prove 和 save

Proof::prove 输入 pp、pk、递归证明对象，输出 CompressedSNARK。当前导出的是库提供零知识处理的压缩证明。

RecursiveSNARK 包含私有 witness 相关数据，程序不将它写入文件交给验证者。proof.bin 只保存压缩证明及产物头部，不保存 EditCircuit.source_block。

错误 witness 可能在证明构造、自检或后续验证中失败，并不保证一定先生成一个完整的无效证明文件。

## 10. verify：验证者不需要原文件

main 中的完整调用顺序：

~~~text
main 的 verify 分支
  → read_statement(public.json) → public
  → public.circuit() → (circuit, z0)
  → Shape::from(&circuit) → shape
  → load(vk.bin, "verifier", &shape) → vk
  → load(proof.bin, "proof", &shape) → proof
  → proof.verify(&vk, circuit.steps, &z0) → output
  → circuit.completed(&z0, &output) → bool
  → 两项都通过后打印 verified: true
~~~

proof.verify 输入验证密钥、步数和初始状态，返回经过证明验证的最终状态。completed 再检查业务是否完成。

verify 不读取原文件，不调用 set_source_step，不重新执行 Myers。这里 circuit.source_block 仍为零，验证时不拿它当原文 witness。

验证者根据自己的 public.json 重建 z0。更换新文或脚本后，即使形状相同，也要针对新的公开输入重新证明；参数可以复用，不代表旧证明可以复用。

## 11. artifact.rs 的文件辅助函数

### 11.1 save(path, kind, shape, value)

输入输出路径、产物类型、形状、对象；输出成功或错误。文件格式是：

~~~text
MAGIC 格式标记 + bincode 编码的 (kind, shape, value)
~~~

当前格式标记为 VALIS-NOVA-DUAL-STREAM-V6，末尾还带一个零字节。这是二进制格式标识，与已删除的 JSON version 字段不是一回事。

kind 为 prover、verifier 或 proof。value 分别是 (pp,pk)、vk 或压缩证明。

### 11.2 load(path, kind, shape)

输入路径、期望类型、期望形状，输出解码后的对象。

依次读取文件、检查格式标记、解码，再检查是否有尾随数据、类型是否匹配、Shape 是否匹配。任何一步出错都返回错误。

这些只是文件格式与兼容性检查，不能替代证明验证，也不能证明随意提供的验证密钥就是预期电路的密钥。验证者应使用自己认可的 setup 产生的 vk。

### 11.3 distinct_paths(paths) 和 normalized(path)

distinct_paths 输入路径数组，输出成功或错误。内部逐个调用 normalized，比较规范化后的路径是否重复。

normalized 输入路径，输出 PathBuf。已有路径直接 canonicalize；尚未创建的输出文件先规范化父目录，再拼接文件名。这能识别普通的相对路径别名，减少覆盖输入文件的情况。

这些函数是普通文件辅助逻辑，不参与编辑正确性的约束。

## 12. 为什么能固定单步形状，什么时候重新 setup

固定形状的方式是：

1. 每块总是编码成 34 个数。
2. 每步总是生成 32 个槽位的完整约束。
3. keep、delete、insert 的规则都存在，通过启用标志决定哪些规则生效。

将 keep(2) 改成 delete(2)，不会删掉一部分约束，而是改变启用标志。因此操作类型和有效长度改变时，单步结构可以保持相同。

chunks 和 EditCircuit::statement 中的 match 在电路外拆分、编码数据，不是在根据操作类型生成不同形状的约束。

但当前以下尺寸仍然影响形状：

| 尺寸 | 影响 |
| --- | --- |
| old_len | 仍作为长度绑定和上界约束的常量，并保留在 Shape 中；不再决定私有变量数或原文查找表大小 |
| new_len | 消费上界的常量；不再决定状态长度、范围检查数或查找规模 |
| steps | 操作表长度、操作行选择器大小 |
| BLOCK | 每行宽度、槽位数量、长度选择器大小 |

在约束代码及库配置不变的前提下，原文长度、新文长度、分块后块数都不变，可以复用 setup。原文内容、新文内容、操作类型、编辑位置、有效长度和插入内容可以改变，但仍需满足尺寸条件，重新生成证明。

只保持文件长度不变还不够：编辑位置改变可能导致块数变化。例如 keep(8) 是一块，而被其他操作隔开的两段 keep(4) 会各占一块。

当前没有把文本填充到固定 50 字节，也没有将块数填充到固定 8 块。**32 是每块最多处理的字节数，不是块数上限。**

虽然 Nova 支持递归，但本程序将整张操作表放进状态，所以总块数变化仍会改变当前形状。

修改约束逻辑或后端配置也应重新生成参数。Shape 只记录四个尺寸，不是源码版本或完整电路的指纹。

## 13. Poseidon 哈希链的定义、函数与证明范围

使用 nova-snark 0.76.0 内置的 Poseidon 实现，不自行设计轮常数。参数为业务电路的 F 域、U5 sponge、Strength::Standard、Simplex 模式。每次使用固定 IO 模式 Absorb(3)、Squeeze(1)，输出完整域元素，不截断。

~~~text
h₀ = Poseidon(INIT_DOMAIN, 0, salt)
hᵢ₊₁ = Poseidon(BYTE_DOMAIN, hᵢ, 原文字节ᵢ)
C = Poseidon(FINAL_DOMAIN, hₙ, 原文长度)
BYTE_DOMAIN  = 0x56414c495301
FINAL_DOMAIN = 0x56414c495302
INIT_DOMAIN  = 0x56414c495303
~~~

hashchain.rs 中的调用关系：

| 函数 | 输入 | 输出及作用 |
| --- | --- | --- |
| constants() | 无 | OnceLock 缓存的 Poseidon 参数，电路内外共用 |
| pattern() | 无 | 固定吸收 3 个元素、输出 1 个元素的 IO 模式 |
| hash(domain, state, item) | 域标记、链状态、字节或长度 | 普通 Rust Poseidon 结果，调用 constants 和 pattern |
| commitment(bytes, salt) | 原文全部字节、私有盐 | 先计算带盐初始链，再逐字节调用 hash，最后调用 finish 返回 C |
| finish(state, len) | 最终链状态、原文长度 | 使用 FINAL_DOMAIN 调用 hash，得到最终承诺 |
| absorb_if(cs, state, byte, enabled) | 约束容器、链状态、字节、启用位 | 用相同参数生成 Poseidon 约束，再约束条件选择，返回下一链变量 |
| encode(value) | 承诺域元素 | 将 to_repr 小端字节编码为 64 位小写十六进制字符串 |
| decode(text) | JSON 承诺字符串 | 检查长度、字符和规范域元素编码，返回 F；不检查 witness 内容 |

diff 调用 commitment 和 encode 写入 JSON。各阶段的 Statement::circuit 调用 decode，仅做格式检查。prove 不预先比较 witness 的承诺，而是由单步链更新和 completed 的终态匹配保证正确性。

哈希按字节计算，因此相同原文无论如何拆分编辑操作，承诺都一样。长度最终绑定区分不同长度的消息，三个域标记区分带盐初始化、字节更新和结束操作。

完整验证通过表示：存在一份匹配公开承诺的私有原文，能够按脚本得到公开新文。每步只分配当前原文片段，消费字节通过递归链状态按顺序累计，最终绑定到同一承诺。验证者必须事先认可 C 属于预期原文件；如果证明者同时替换原文和 C，不能仅凭证明确认外部文件身份。

最终链值属于证明的最终状态，应视为公开数据，不依赖其保密性。

当前使用系统随机源生成的私有盐。盐不公开，也不将带盐初始链值放入 z0；仅知道公开承诺不能直接枚举原文并比较无盐哈希。若盐泄露，可猜测的原文仍可能被离线枚举。新文、原文长度和脚本也仍公开，keep 内容可从新文推断。

本次增加两个状态字段和每步32 组 Poseidon 约束，必须重新 diff/setup/prove。旧无承诺 JSON 和 V2 产物不能复用。新参数可以用于相同尺寸但不同承诺的输入。原文承诺不再允许仅改变删除内容而保持同一公开语句通过证明。

原文侧现在只有 32 个字节槽的范围检查，不再有全文原文查找。新文仍做全文范围检查和线性查找，操作表也保持原样。每步仍固定计算 32 组候选哈希，并新增一次原文长度上界检查。

## 14. 时间输出和现有测试

程序使用 Instant 计时，以 as_secs_f64() 转成秒，保留 6 位小数。

| 输出 | 计时范围 |
| --- | --- |
| myers | myers_diff |
| setup | PP::setup + Proof::setup |
| prove | RecursiveSNARK::new + 全部 prove_step + Proof::prove |
| prover self-check | recursive.verify + completed，单独计时 |
| verify | proof.verify + completed |

文件读取、输入编码、拆块和产物序列化写入等，不计入上述密码学阶段计时。proof 字节数是最终产物文件大小，包括头部。

现有 CLI 集成测试在 [tests/cli.rs](tests/cli.rs)，可运行：

~~~powershell
cargo test --release
~~~

阅读代码时，按本文顺序从 main 的 diff 开始，进入 Statement::circuit，再回到 setup/prove，在 prove_step 处查看 synthesize，最后回到 completed 和 verify，就能将数据准备、单步规则、递归证明和最终接受条件对应起来。

当前 BLOCK 为 32。当前 V5 引入私有盐，旧无盐承诺及参数需要重新 diff/setup/prove。

## 15. 原文片段优化后的长度检查与兼容性

enforce_source_bound(cs, consumed, old_len) 输入本步结束后的原文游标和原文总长度，无新状态返回，只添加约束。它将剩余长度分解成 8 个字节（64 位），逐个检查字节范围，并要求 consumed + remaining == old_len。游标从零开始，每步最多加 32，因此不会通过有限域绕回伪造负的剩余长度。

原文片段优化曾将格式升级到 V4；当前加入私有盐后为 V5，必须重新 diff/setup/prove。块容量和新文侧处理仍不变。

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
