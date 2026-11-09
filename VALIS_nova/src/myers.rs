use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Edit {
    Keep(usize),
    Delete(usize),
    Insert(Vec<u8>),
}

impl fmt::Display for Edit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keep(n) => write!(f, "keep({n})"),
            Self::Delete(n) => write!(f, "delete({n})"),
            Self::Insert(text) => write!(f, "insert({text:?})"),
        }
    }
}

pub fn myers_diff(old: &[u8], new: &[u8]) -> Vec<Edit> {
    let a = old;
    let b = new;
    if a.is_empty() {
        return if b.is_empty() {
            vec![]
        } else {
            vec![Edit::Insert(new.into())]
        };
    }
    if b.is_empty() {
        return vec![Edit::Delete(a.len())];
    }

    let max = a.len() + b.len();
    let offset = max as isize + 1;
    let index = |k: isize| (offset + k) as usize;
    let mut v = vec![0usize; 2 * max + 3];
    let mut trace = Vec::new();
    let mut distance = 0;

    'search: for d in 0..=max {
        let depth = d as isize;
        for k in (-depth..=depth).step_by(2) {
            let mut x = if k == -depth || (k != depth && v[index(k - 1)] < v[index(k + 1)]) {
                v[index(k + 1)] // Insert from the next diagonal.
            } else {
                v[index(k - 1)] + 1 // Delete from the previous diagonal.
            };
            let mut y = (x as isize - k) as usize;
            while x < a.len() && y < b.len() && a[x] == b[y] {
                x += 1;
                y += 1;
            }
            v[index(k)] = x;
            if x == a.len() && y == b.len() {
                distance = d;
                trace.push(v.clone());
                break 'search;
            }
        }
        trace.push(v.clone());
    }

    let (mut x, mut y) = (a.len(), b.len());
    let mut reversed = Vec::new();
    for d in (1..=distance).rev() {
        let previous = &trace[d - 1];
        let k = x as isize - y as isize;
        let depth = d as isize;
        let previous_k =
            if k == -depth || (k != depth && previous[index(k - 1)] < previous[index(k + 1)]) {
                k + 1
            } else {
                k - 1
            };
        let previous_x = previous[index(previous_k)];
        let previous_y = (previous_x as isize - previous_k) as usize;
        while x > previous_x && y > previous_y {
            reversed.push(Edit::Keep(1));
            x -= 1;
            y -= 1;
        }
        if x == previous_x {
            y -= 1;
            reversed.push(Edit::Insert(vec![b[y]]));
        } else {
            x -= 1;
            reversed.push(Edit::Delete(1));
        }
    }
    // The d=0 path consists entirely of a common prefix.
    if x > 0 {
        reversed.push(Edit::Keep(x));
    }
    reversed.reverse();

    let mut result = Vec::new();
    for edit in reversed {
        match (result.last_mut(), edit) {
            (Some(Edit::Keep(n)), Edit::Keep(m)) => *n += m,
            (Some(Edit::Delete(n)), Edit::Delete(m)) => *n += m,
            (Some(Edit::Insert(text)), Edit::Insert(more)) => text.extend(more),
            (_, edit) => result.push(edit),
        }
    }
    result
}
