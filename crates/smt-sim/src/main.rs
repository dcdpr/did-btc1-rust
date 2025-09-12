use crate::smt::{Smt, SmtNih, SmtRocks, SmtSled, SmtSqlite, hash_concat};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use smt::Hash;
use std::collections::BTreeMap;
use std::io::{BufWriter, Write as _};
use std::{cell::RefCell, fmt::Write as _, fs::File, process::Command, time::Instant};

#[cfg(target_os = "windows")]
use std::os::windows::fs::MetadataExt as _;

#[cfg(target_os = "macos")]
use std::os::darwin::fs::MetadataExt as _;

#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt as _;

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

fn random_size(n: usize) -> usize {
    if n == 1 {
        1
    } else {
        PRNG.with(|prng| prng.borrow_mut().r#gen_range(1..n))
    }
}

/// Re-seed the PRNG with its default settings.
fn reseed_prng() {
    PRNG.with(|prng| prng.replace(StdRng::from_seed(DEFAULT_PRNG_SEED)));
}

fn main() {
    // Run the proof creator/printer
    create_proof();

    // Run all the benchmarks
    if std::env::args().nth(1) == Some("--bench-tree".to_string()) {
        benchmark_tree::<SmtNih>();
        benchmark_tree::<SmtSqlite>();
        benchmark_tree::<SmtRocks>();
        benchmark_tree::<SmtSled>();
    }

    if std::env::args().nth(1) == Some("--bench-proof".to_string()) {
        benchmark_proof::<SmtNih>();
    }
}

fn create_kv_pairs(num: usize) -> Vec<(Hash, Hash)> {
    let mut kv_pairs = Vec::with_capacity(num);

    for _ in 0..num {
        kv_pairs.push((random_hash(), random_hash()));
    }
    kv_pairs
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

    let smt = SmtNih::new(db_path).unwrap();
    let kv_pairs = create_kv_pairs(total_nodes);

    let root = smt_demo(&smt, &kv_pairs, with_diagrams);

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

fn benchmark_tree<T>()
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

        let smt = T::new(&db_path).unwrap();
        let kv_pairs = create_kv_pairs(size);

        smt_demo(&smt, &kv_pairs, false);

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

fn benchmark_proof<T>()
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    reseed_prng();

    // Get the raw size of proofs for:
    // - N = cohort size
    // - M = %mine
    // - U = average updates per block by others (i.e., how many updates in the tree)
    //   - NOTE: When "use-nonce" is true, U = 1.0 (every user always updates)

    // let sizes = [5, 10, 100, 1_000, 10_000, 50_000, 100_000, 1_000_000];
    let sizes = [100];

    for size in sizes {
        // TODO: Make this a struct
        // Stores a sparse 2D array of proof sizes (in bytes) by [M,U] coordinates.
        let mut surface: BTreeMap<u64, BTreeMap<u64, u64>> = BTreeMap::new();

        let db_path = format!("./db/smt-sim-{}.{}", human_size(size), T::EXT);

        // Remove old DB (if any)
        Command::new("rm").args(["-rf", &db_path]).output().unwrap();

        let my_percentages = [0.0, 0.01, 0.05, 0.1, 0.25, 0.5, 0.75];

        for m in my_percentages {
            let my_did_count = (size as f64 * m) as usize;

            let smt = T::new(&db_path).unwrap();
            let kv_pairs = create_kv_pairs(size);

            let mut i = 0;
            let (mine, not_mine): (Vec<_>, Vec<_>) = kv_pairs.into_iter().partition(|_| {
                i += 1;

                i < my_did_count
            });

            let max_possible_updates = size as f64 * (1.0 - m);

            // todo: is currently pulling from Uniform, we want gaussian?
            let ave_num_updates = random_size(max_possible_updates as usize);

            // Insert all updates into the tree
            let root = smt_demo(&smt, &not_mine[..ave_num_updates], false);

            // Create all of my proofs of non-inclusion
            let my_proofs = mine
                .into_iter()
                .map(|(key, _)| smt.get_proof(&root, &key))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            // Write all proofs to disk
            let proof_path = format!("./db/smt-sim-{}-{m}.proof", human_size(size));
            write_proofs::<T>(&proof_path, &my_proofs);

            let proof_size = Command::new("du")
                .args(["-hs", &proof_path])
                .output()
                .unwrap();
            println!("{}", String::from_utf8_lossy(&proof_size.stdout).trim());

            let proof_metadata = std::fs::metadata(&proof_path).unwrap();

            #[cfg(target_os = "windows")]
            let proof_size_in_bytes = proof_metadata.file_size();

            #[cfg(any(target_os = "macos", target_os = "linux"))]
            let proof_size_in_bytes = proof_metadata.st_size();

            let entry = surface.entry(my_did_count as u64).or_default();
            entry.insert(ave_num_updates as u64, proof_size_in_bytes);
        }

        draw_chart(size as u64, surface);
    }
}

fn write_proofs<T: Smt>(proof_path: &str, proofs: &[T::Proof]) {
    let file = File::create(proof_path).unwrap();
    let mut writer = BufWriter::new(&file);
    bincode::encode_into_std_write(proofs, &mut writer, bincode::config::standard()).unwrap();
    writer.flush().unwrap();
}

fn smt_demo<T>(smt: &T, kv_pairs: &[(Hash, Hash)], diagrams: bool) -> Hash
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    let mut root = None;

    let tx = smt.prepare();
    for (i, (key, value)) in kv_pairs.iter().enumerate() {
        root = smt.insert(root.as_ref(), key, value).unwrap();

        if diagrams && let Some(diagram) = smt.render(&root.unwrap()) {
            std::fs::write(format!("smt.{i}.mmd"), diagram).unwrap();
        }
    }
    smt.commit(tx);

    root.unwrap()
}

fn human_size(size: usize) -> String {
    match size {
        0..1_000 => format!("{size}"),
        1_000..1_000_000 => format!("{}K", size / 1_000),
        1_000_000..1_000_000_000 => format!("{}M", size / 1_000_000),
        _ => panic!("My spoon is too big!"),
    }
}

fn draw_chart(cohort_size: u64, surface: BTreeMap<u64, BTreeMap<u64, u64>>) {
    use plotters::prelude::*;

    let filename = format!("surface_{cohort_size}.svg");
    let drawing_area =
        SVGBackend::new(&filename, (640, 480)).into_drawing_area();
    drawing_area.fill(&WHITE).unwrap();

    let mut chart_context = ChartBuilder::on(&drawing_area)
        .margin(10)
        .build_cartesian_3d(0..cohort_size, 0..cohort_size, 0..cohort_size)
        .unwrap();
    chart_context.configure_axes().draw().unwrap();

    let axis_title_style = ("sans-serif", 20, &BLACK).into_text_style(&drawing_area);
    chart_context
        .draw_series(
            [
                ("x", (cohort_size, 0, 0)),
                ("y", (0, cohort_size, 0)),
                ("z", (0, 0, cohort_size)),
            ]
            .map(|(label, position)| Text::new(label, position, &axis_title_style)),
        )
        .unwrap();

    chart_context
        // .draw_series(
        //     SurfaceSeries::xoz(
        //         (-30..30).map(|v| v as f64 / 10.0),
        //         (-30..30).map(|v| v as f64 / 10.0),
        //         |x: f64, z: f64| (0.4 * (x * x + z * z)).cos(),
        //     )
        //     .style_func(&|y| HSLColor(0.6666, y + 0.5, 0.5).mix(0.8).filled()),
        // )
        .draw_series(
            SurfaceSeries::xoz(
                0..cohort_size,
                0..cohort_size,
                |x: u64, z: u64| {
                    surface.get(&x).and_then(|t| t.get(&z).copied()).unwrap_or_default()
                }
            )
                .style_func(&|y| HSLColor(0.6666, *y as f64 + 0.5, 0.5).mix(0.8).filled()),
        )
        .unwrap();
}
