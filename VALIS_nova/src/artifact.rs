use crate::circuit::{EditCircuit, BLOCK};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAGIC: &[u8] = b"VALIS-NOVA-SOURCE-BLOCK-V4\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Shape {
    block: usize,
    old_len: usize,
    new_len: usize,
    steps: usize,
}
impl From<&EditCircuit> for Shape {
    fn from(c: &EditCircuit) -> Self {
        Self {
            block: BLOCK,
            old_len: c.old_len,
            new_len: c.new_len,
            steps: c.steps,
        }
    }
}

pub(crate) fn save<T: Serialize>(
    path: impl AsRef<Path>,
    kind: &str,
    shape: &Shape,
    value: &T,
) -> Result<()> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend(bincode::serde::encode_to_vec(
        (kind, shape, value),
        bincode::config::standard(),
    )?);
    fs::write(path, bytes)?;
    Ok(())
}

pub(crate) fn load<T: DeserializeOwned>(
    path: impl AsRef<Path>,
    kind: &str,
    shape: &Shape,
) -> Result<T> {
    let bytes = fs::read(path)?;
    let payload = bytes
        .strip_prefix(MAGIC)
        .ok_or("unsupported artifact version; run setup again")?;
    let ((actual_kind, actual_shape, value), used): ((String, Shape, T), usize) =
        bincode::serde::decode_from_slice(payload, bincode::config::standard())?;
    if used != payload.len() {
        return Err("trailing artifact data".into());
    }
    if actual_kind != kind {
        return Err("wrong artifact type".into());
    }
    if actual_shape != *shape {
        return Err("artifact shape mismatch; run setup again".into());
    }
    Ok(value)
}

// 规范化父目录，防止输出通过相对路径别名覆盖输入文件。
fn normalized(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return Ok(path.canonicalize()?);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or("invalid output path")?;
    Ok(parent.canonicalize()?.join(name))
}
pub(crate) fn distinct_paths(paths: &[&Path]) -> Result<()> {
    let mut seen = Vec::new();
    for path in paths {
        let normalized = normalized(path)?;
        if seen.contains(&normalized) {
            return Err("input and output paths must differ".into());
        }
        seen.push(normalized);
    }
    Ok(())
}
