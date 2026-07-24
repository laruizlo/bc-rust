//! Compile-smoke bench: proves the criterion + `bench-internals` wiring exists.
//! Real benchmarks land with the arithmetic layer (phase 2), where there is
//! something meaningful to measure.

use criterion::{Criterion, criterion_group, criterion_main};

fn smoke(c: &mut Criterion) {
    c.bench_function("smoke_noop", |b| b.iter(|| core::hint::black_box(0u64)));
}

criterion_group!(benches, smoke);
criterion_main!(benches);
