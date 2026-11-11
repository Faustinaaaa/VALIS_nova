//! 公开输入的格式定义与电路输入编码，不提前判断编辑操作是否正确。
use crate::{
    circuit::{chunks, EditCircuit, BLOCK, F},
    myers::Edit,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Statement {
    pub before_len: usize,
    pub before_commitment: String,
    pub after: Vec<u8>,
    pub edits: Vec<Edit>,
}

impl Statement {
    /// 把当前公开输入转换成电路对象和初始状态。这些工作都在电路外完成。
    /// &self：读取当前 Statement，不修改它。
    /// 成功时返回 (EditCircuit, Vec<F>)：电路对象和初始状态 z0。
    /// F 是电路使用的数字类型；Vec<F> 就是这些数字组成的数组。
    /// 失败时返回 String：说明错误原因的文字。
    /// 这里只检查格式和数据大小，不检查编辑操作是否正确，也不生成证明。
    pub fn circuit(&self) -> Result<(EditCircuit, Vec<F>), String> {
        // 先计算编辑脚本一共会拆成多少块，初始为 0。
        let mut blocks = 0usize;
        for edit in &self.edits {
            let n = match edit {
                Edit::Keep(n) | Edit::Delete(n) => *n,
                Edit::Insert(bytes) => bytes.len(),
            };
            blocks = blocks
                .checked_add(n / BLOCK + usize::from(n % BLOCK != 0))
                .ok_or("encoded block count overflow")?;
        }
        // 即使没有操作，也至少保留一步；后面的 chunks 会生成 keep(0)。
        let blocks = blocks.max(1);
        // 计算初始状态需要多少个 F 元素，不是计算文件有多少字节。
        let state_len = blocks
            .checked_mul(2 + BLOCK)
            .and_then(|n| n.checked_add(self.after.len()))
            .and_then(|n| n.checked_add(6))
            .ok_or("encoded state size overflow")?;
        // 检查两个数组的大小：初始状态数组，以及固定容量的私有原文片段。
        for len in [state_len, BLOCK] {
            if len
                // 元素数量乘以一个 F 占用的字节数，得到数组所需的字节数。
                .checked_mul(std::mem::size_of::<F>())
                // 乘法溢出，或超过 Vec 允许的分配大小，就拒绝。
                // 这里只检查大小是否合法，不保证机器有足够的空闲内存。
                .is_none_or(|bytes| bytes > isize::MAX as usize)
            {
                return Err("input allocation size overflow".into());
            }
        }
        // 真正拆分脚本，得到每块最多 BLOCK 字节的操作列表 tape。
        let tape = chunks(&self.edits);
        // 将 JSON 中的十六进制承诺字符串转换成 F。
        // 只检查编码是否合法，不在这里检查承诺是否与原文匹配。
        let commitment = crate::hashchain::decode(&self.before_commitment)?;
        // 根据下面四个输入，构造电路对象和初始状态，再用 Ok 返回。
        // 此时私有片段的 BLOCK 个槽先填零，prove 阶段逐步装入对应片段。
        Ok(EditCircuit::statement(
            // 原文总字节数。
            self.before_len,
            // 新文的全部字节。
            &self.after,
            // 拆分后的编辑块。
            &tape,
            // 公开的原文承诺。
            commitment,
        ))
    }
}
