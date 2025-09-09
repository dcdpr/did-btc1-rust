use crate::smt::{Smt, SmtRocks, SmtSled, SmtSqlite, hash_concat};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use smt::Hash;
use std::{cell::RefCell, fmt::Write as _, process::Command, time::Instant};

mod smt;

const DEFAULT_PRNG_SEED: [u8; 32] = [
    // echo -n 'https://xkcd.com/221/' | sha256sum
    0x62, 0xbe, 0xf7, 0x04, 0x85, 0xaf, 0x17, 0x10, 0x26, 0x53, 0x68, 0xee, 0x4d, 0x89, 0x11, 0x22,
    0x8a, 0xc6, 0x3c, 0x93, 0x62, 0x83, 0xa4, 0x19, 0x59, 0x1e, 0xc9, 0x37, 0xb6, 0x79, 0x88, 0xef,
];

thread_local! {
    /// Deterministic PRNG seeded with an arbitrarily chosen SHA-256 hash.
    ///
    /// Because it's thread-local, multiple threads will not be able to deterministically share the
    /// PRNG state.
    static PRNG: RefCell<StdRng> = RefCell::new(StdRng::from_seed(DEFAULT_PRNG_SEED));
}

/// Re-implement [`monotree::utils::random_hash`] with a deterministic PRNG.
fn random_hash() -> Hash {
    PRNG.with(|prng| prng.borrow_mut().r#gen())
}

/// Re-seed the PRNG with its default settings.
fn reseed_prng() {
    PRNG.with(|prng| prng.replace(StdRng::from_seed(DEFAULT_PRNG_SEED)));
}

fn main() {
    // Run the proof creator/printer
    create_proof();

    // Run all the benchmarks
    if std::env::args().nth(1) == Some("--bench".to_string()) {
        benchmark::<SmtSqlite>();
        benchmark::<SmtRocks>();
        benchmark::<SmtSled>();
    }
}

fn create_proof() {
    reseed_prng();

    let db_path = "./db/smt-sim.sqlite";

    // Remove old DB (if any)
    Command::new("rm").args(["-rf", db_path]).output().unwrap();

    // let (smt, root) = smt_demo::<SmtSqlite>(db_path, 10_000);
    let (smt, root) = smt_demo_with_diagrams(db_path, 4);

    let key = random_hash();
    let value = random_hash();
    let leaf = hash_concat(&key, &value);
    let root = smt.insert(Some(&root), &key, &value).unwrap();

    let proof = smt.get_proof(root.as_ref(), &key).unwrap().unwrap();

    println!("key: {}", hex::encode(key));
    println!("value: {}", hex::encode(value));
    println!("root: {}", hex::encode(root.unwrap()));
    println!("leaf: {}", hex::encode(leaf));
    println!("proof: {proof}");
    // println!("proof: {}", print_proof(&proof)); // for monotree

    std::fs::write("smt.mmd", smt.render(&root.unwrap()).unwrap()).unwrap();

    proof.verify(&root.unwrap(), &key, &value).unwrap();
}

fn print_proof(proof: &[(bool, Vec<u8>)]) -> String {
    let mut pretty = String::new();

    writeln!(&mut pretty, "[").unwrap();
    for (direction, hash) in proof {
        writeln!(
            &mut pretty,
            "    {}: {},",
            if *direction { 1 } else { 0 },
            hex::encode(hash)
        )
        .unwrap();
    }
    writeln!(&mut pretty, "]").unwrap();

    pretty
}

fn benchmark<T>()
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    reseed_prng();

    // 1 million is way too much
    // (the example with RocksDB takes 183 seconds to run on J's machine - AMD 5900x)
    // (the example with RocksDB takes 72 seconds to run on D's machine - Apple M3, 2024)
    let sizes = [1, 5, 10, 100, 1_000, 10_000, 50_000, 100_000];

    for size in sizes {
        let db_path = format!("./db/smt-sim-{}.{}", human_size(size), T::EXT);

        // Remove old DB (if any)
        Command::new("rm").args(["-rf", &db_path]).output().unwrap();

        let start = Instant::now();

        smt_demo::<T>(&db_path, size);

        println!(
            "Created `{db_path}` in {:?}",
            Instant::now().duration_since(start),
        );
    }

    println!();

    for size in sizes {
        let dbpath = format!("./db/smt-sim-{}.{}", human_size(size), T::EXT);

        // Get the DB's size on disk
        let db_size = Command::new("du").args(["-hs", &dbpath]).output().unwrap();
        println!("{}", String::from_utf8_lossy(&db_size.stdout).trim());
    }

    println!();
}

fn smt_demo<T>(db_path: &str, cohort_size: u64) -> (T, Hash)
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    let smt = T::new(db_path).unwrap();
    let mut root = None;

    smt.prepare();
    for _ in 0..cohort_size {
        let key = random_hash();
        let leaf = random_hash();
        root = smt.insert(root.as_ref(), &key, &leaf).unwrap();
    }
    smt.commit();

    (smt, root.unwrap())
}

fn smt_demo_with_diagrams(db_path: &str, cohort_size: u64) -> (SmtSqlite, Hash) {
    let smt = SmtSqlite::new(db_path).unwrap();
    let mut root = None;

    smt.prepare();
    for i in 0..cohort_size {
        let key = random_hash();
        let leaf = random_hash();
        root = smt.insert(root.as_ref(), &key, &leaf).unwrap();
        std::fs::write(format!("smt.{i}.mmd"), smt.render(&root.unwrap()).unwrap()).unwrap();
    }
    smt.commit();

    (smt, root.unwrap())
}

fn human_size(size: u64) -> String {
    match size {
        0..1_000 => format!("{size}"),
        1_000..1_000_000 => format!("{}K", size / 1_000),
        1_000_000..1_000_000_000 => format!("{}M", size / 1_000_000),
        _ => panic!("My spoon is too big!"),
    }
}

#[allow(dead_code)]
fn example_diagram() {
    use plotters::prelude::*;

    let drawing_area =
        SVGBackend::new("surface_series_style_func.svg", (640, 480)).into_drawing_area();
    drawing_area.fill(&WHITE).unwrap();

    let mut chart_context = ChartBuilder::on(&drawing_area)
        .margin(10)
        .build_cartesian_3d(-3.0..3.0f64, -3.0..3.0f64, -3.0..3.0f64)
        .unwrap();
    chart_context.configure_axes().draw().unwrap();

    let axis_title_style = ("sans-serif", 20, &BLACK).into_text_style(&drawing_area);
    chart_context
        .draw_series(
            [
                ("x", (3., -3., -3.)),
                ("y", (-3., 3., -3.)),
                ("z", (-3., -3., 3.)),
            ]
            .map(|(label, position)| Text::new(label, position, &axis_title_style)),
        )
        .unwrap();
    chart_context
        .draw_series(
            SurfaceSeries::xoz(
                (-30..30).map(|v| v as f64 / 10.0),
                (-30..30).map(|v| v as f64 / 10.0),
                |x: f64, z: f64| (0.4 * (x * x + z * z)).cos(),
            )
            .style_func(&|y| HSLColor(0.6666, y + 0.5, 0.5).mix(0.8).filled()),
        )
        .unwrap();
}
