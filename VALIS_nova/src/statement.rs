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
    pub after: Vec<u8>,
    pub edits: Vec<Edit>,
}

impl Statement {
    pub fn circuit(&self) -> Result<(EditCircuit, Vec<F>), String> {
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
        let blocks = blocks.max(1);
        let state_len = blocks
            .checked_mul(2 + BLOCK)
            .and_then(|n| n.checked_add(self.after.len()))
            .and_then(|n| n.checked_add(4))
            .ok_or("encoded state size overflow")?;
        for len in [state_len, self.before_len] {
            if len
                .checked_mul(std::mem::size_of::<F>())
                .is_none_or(|bytes| bytes > isize::MAX as usize)
            {
                return Err("input allocation size overflow".into());
            }
        }
        let tape = chunks(&self.edits);
        Ok(EditCircuit::statement(self.before_len, &self.after, &tape))
    }
}
