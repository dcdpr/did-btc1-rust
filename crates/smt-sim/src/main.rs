use monotree::database::{rocksdb::RocksDB, sled::Sled};
use monotree::{Database, Hash, Monotree, hasher::Sha2, utils::random_hash};
use std::{fmt::Write as _, time::Instant};

fn main() {
    // // Run all the benchmarks
    // benchmark::<RocksDB>();
    // benchmark::<Sled>();

    // Run the proof creator/printer
    create_proof();
}

#[allow(dead_code)]
fn create_proof() {
    let (mut monotree, root) = smt_demo::<RocksDB>("./smt-sim.rocksdb", 10_000);

    let key = random_hash();
    let leaf = random_hash();
    let root = monotree.insert(Some(&root), &key, &leaf).unwrap();

    let proof = monotree
        .get_merkle_proof(root.as_ref(), &key)
        .unwrap()
        .unwrap();

    println!("key: {}", hex::encode(key));
    println!("proof: {}", print_proof(&proof));
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

trait DatabaseExt {
    fn db_name() -> &'static str;
}

impl DatabaseExt for RocksDB {
    fn db_name() -> &'static str {
        "rocksdb"
    }
}

impl DatabaseExt for Sled {
    fn db_name() -> &'static str {
        "sled"
    }
}

#[allow(dead_code)]
fn benchmark<T: Database + DatabaseExt>() {
    // 1 million is way too much
    // (the example with RocksDB takes 183 seconds to run on J's machine - AMD 5900x)
    // (the example with RocksDB takes 72 seconds to run on D's machine - Apple M3, 2024)
    for size in [1, 5, 10, 100, 1_000, 10_000, 100_000, 1_000_000] {
        let dbpath = format!("./smt-sim-{}.{}", human_size(size), T::db_name());
        let start = Instant::now();

        smt_demo::<T>(&dbpath, size);

        println!(
            "Created `{dbpath}` in {:?}",
            Instant::now().duration_since(start),
        );
    }
}

fn smt_demo<T: Database>(dbpath: &str, cohort_size: u64) -> (Monotree<T, Sha2>, Hash) {
    let mut monotree = Monotree::<T, Sha2>::new(dbpath);
    let mut root = None;

    monotree.prepare();
    for _ in 0..cohort_size {
        let key = random_hash();
        let leaf = random_hash();
        root = monotree.insert(root.as_ref(), &key, &leaf).unwrap();
    }
    monotree.commit();

    (monotree, root.unwrap())
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
