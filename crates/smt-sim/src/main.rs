use crate::smt::{Smt, SmtNih, SmtRocks, SmtSled, SmtSqlite, hash_concat};
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
        benchmark::<SmtNih>();
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

    let total_nodes = 32;
    let with_diagrams = false;
    println!(
        "Inserting and verifying proofs for {total_nodes} nodes{}...",
        if with_diagrams { " with diagrams" } else { "" },
    );

    let (smt, root, kv_pairs) = smt_demo::<SmtNih>(db_path, total_nodes, with_diagrams);

    println!("root: {}", hex::encode(root));
    println!();

    let mut excluded_hash = kv_pairs[0].0;
    for byte in &mut excluded_hash {
        // Invert all bytes in the hash.
        *byte ^= 0xff;
    }
    if kv_pairs.iter().all(|(k, _)| k != &excluded_hash) {
        let proof = smt.get_proof(&root, &excluded_hash).unwrap();

        println!("Checking proof of non-inclusion...");
        println!("key: {}", hex::encode(excluded_hash));
        println!("proof: {proof}");

        proof
            .verify_noninclusion(&root)
            .expect("must prove non-inclusion");

        println!("Verified the key is not included in the SMT!");
        println!();
    }

    for (key, value) in kv_pairs {
        let proof = smt.get_proof(&root, &key).unwrap();

        println!("key: {}", hex::encode(key));
        println!("value: {}", hex::encode(value));
        println!("leaf: {}", hex::encode(hash_concat(&key, &value)));
        println!("proof: {proof}");
        // println!("proof: {}", print_proof(&proof)); // for monotree

        proof
            .verify(&root, &key, &value)
            .expect("must prove inclusion");
        proof
            .verify_noninclusion(&root)
            .expect_err("cannot prove both inclusion and non-inclusion");

        println!();
    }

    if let Some(diagram) = smt.render(&root) {
        std::fs::write("smt.mmd", diagram).unwrap();
    }

    println!("All proofs verified!");
    println!();
}

#[allow(dead_code)]
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

    // 1 million is effectively beyond the limit for practical purposes. We should include it when
    // running the full benchmark, allowing backends to fail (e.g. don't unwrap, impose timeouts,
    // etc.) It will leave blank spaces in the sequence data for the diagrams. But that's ok.
    //
    // TODO: Is there a nice way to indicate error conditions in diagrams?
    let sizes = [1, 5, 10, 100, 1_000, 10_000, 50_000, 100_000];
    // let sizes = [1, 5, 10, 100, 1_000, 10_000, 50_000, 100_000, 1_000_000];

    for size in sizes {
        let db_path = format!("./db/smt-sim-{}.{}", human_size(size), T::EXT);

        // Remove old DB (if any)
        Command::new("rm").args(["-rf", &db_path]).output().unwrap();

        let start = Instant::now();

        smt_demo::<T>(&db_path, size, false);

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

fn smt_demo<T>(db_path: &str, cohort_size: usize, diagrams: bool) -> (T, Hash, Vec<(Hash, Hash)>)
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    let smt = T::new(db_path).unwrap();
    let mut root = None;
    let mut kv_pairs = Vec::with_capacity(cohort_size);

    let tx = smt.prepare();
    for i in 0..cohort_size {
        let key = random_hash();
        let value = random_hash();
        root = smt.insert(root.as_ref(), &key, &value).unwrap();
        kv_pairs.push((key, value));

        if diagrams && let Some(diagram) = smt.render(&root.unwrap()) {
            std::fs::write(format!("smt.{i}.mmd"), diagram).unwrap();
        }
    }
    smt.commit(tx);

    (smt, root.unwrap(), kv_pairs)
}

fn human_size(size: usize) -> String {
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
