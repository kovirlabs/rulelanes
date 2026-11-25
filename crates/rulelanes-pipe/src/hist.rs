//! A fixed-size latency histogram: exact below 64 ns, then 32 buckets per
//! power of two (about 3% wide). Recording never allocates. Same scheme as
//! the one in `flowlanes-pipe` (written again here, not shared).

const BUCKETS: usize = 1920;

/// Counts of nanosecond values.
#[derive(Clone)]
pub struct Histogram {
    counts: Vec<u64>,
    total: u64,
    max: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Histogram {
            counts: vec![0; BUCKETS],
            total: 0,
            max: 0,
        }
    }
}

fn index(v: u64) -> usize {
    if v < 64 {
        return v as usize;
    }
    let e = 63 - v.leading_zeros();
    let sub = ((v >> (e - 5)) & 31) as usize;
    (e as usize - 5) * 32 + 32 + sub
}

/// Largest value that falls in bucket `i`.
fn upper(i: usize) -> u64 {
    if i < 64 {
        return i as u64;
    }
    let shift = (i - 32) / 32;
    let sub = ((i - 32) % 32) as u64;
    let low = (32 + sub) << shift;
    low + ((1u64 << shift) - 1)
}

impl Histogram {
    /// Records one observation of `nanos`.
    pub fn record(&mut self, nanos: u64) {
        self.counts[index(nanos)] += 1;
        self.total += 1;
        self.max = self.max.max(nanos);
    }

    /// Observations recorded.
    pub fn count(&self) -> u64 {
        self.total
    }

    /// Largest observation.
    pub fn max(&self) -> u64 {
        self.max
    }

    /// The value at quantile `q` (0 to 1): the upper edge of the bucket
    /// that holds it, so never an underestimate. `None` when empty.
    pub fn quantile(&self, q: f64) -> Option<u64> {
        if self.total == 0 {
            return None;
        }
        let target = ((q * self.total as f64).ceil() as u64).clamp(1, self.total);
        let mut seen = 0;
        for (i, &c) in self.counts.iter().enumerate() {
            seen += c;
            if seen >= target {
                return Some(upper(i).min(self.max));
            }
        }
        Some(self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_contiguous_and_ordered() {
        let mut last = 0;
        for v in [0u64, 1, 63, 64, 65, 127, 128, 1000, 1 << 20, u64::MAX] {
            let i = index(v);
            assert!(i >= last && i < BUCKETS, "{v}");
            assert!(upper(i) >= v, "{v}");
            if i > 0 {
                assert!(upper(i - 1) < v, "{v}");
            }
            last = i;
        }
    }

    #[test]
    fn quantiles() {
        let mut h = Histogram::default();
        assert_eq!(h.quantile(0.5), None);
        for v in 1..=100u64 {
            h.record(v * 1000);
        }
        let p50 = h.quantile(0.5).expect("p50");
        assert!((50_000..=52_000).contains(&p50), "{p50}");
        assert_eq!(h.quantile(1.0), Some(100_000));
        assert_eq!(h.count(), 100);
    }
}
