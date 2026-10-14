//! Bounds-safe little-endian reader over a byte slice.
//!
//! Every accessor returns `Option` so malformed samples never panic.

#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn u8(&self, off: usize) -> Option<u8> {
        self.data.get(off).copied()
    }

    pub fn u16(&self, off: usize) -> Option<u16> {
        let b = self.bytes(off, 2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&self, off: usize) -> Option<u32> {
        let b = self.bytes(off, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&self, off: usize) -> Option<u64> {
        let b = self.bytes(off, 8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(u64::from_le_bytes(a))
    }

    pub fn bytes(&self, off: usize, len: usize) -> Option<&'a [u8]> {
        let end = off.checked_add(len)?;
        self.data.get(off..end)
    }

    /// Bytes from `off` clamped to the end of the data (never fails unless `off` is out of range).
    pub fn bytes_clamped(&self, off: usize, len: usize) -> &'a [u8] {
        if off >= self.data.len() {
            return &[];
        }
        let end = off.saturating_add(len).min(self.data.len());
        &self.data[off..end]
    }

    /// Zero-terminated ASCII/ANSI string, capped at `max` bytes.
    pub fn cstr(&self, off: usize, max: usize) -> Option<String> {
        let tail = self.data.get(off..)?;
        let tail = &tail[..tail.len().min(max)];
        let end = tail.iter().position(|&c| c == 0).unwrap_or(tail.len());
        Some(String::from_utf8_lossy(&tail[..end]).into_owned())
    }

    /// Zero-terminated UTF-16LE string, capped at `max_chars` characters.
    pub fn wstr(&self, off: usize, max_chars: usize) -> Option<String> {
        let mut units = Vec::new();
        let mut o = off;
        while units.len() < max_chars {
            let c = self.u16(o)?;
            if c == 0 {
                break;
            }
            units.push(c);
            o += 2;
        }
        Some(String::from_utf16_lossy(&units))
    }

    /// Counted UTF-16LE string (`count` characters).
    pub fn wstr_n(&self, off: usize, count: usize) -> Option<String> {
        let b = self.bytes(off, count.checked_mul(2)?)?;
        let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).collect();
        Some(String::from_utf16_lossy(&units))
    }
}

pub fn align_up(v: u64, a: u64) -> u64 {
    if a == 0 {
        return v;
    }
    v.div_ceil(a).saturating_mul(a)
}

pub fn align_down(v: u64, a: u64) -> u64 {
    if a == 0 {
        return v;
    }
    v / a * a
}
