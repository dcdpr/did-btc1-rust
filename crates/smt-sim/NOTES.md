# Dan (Unbatched)

sled DB dir creation times on macos:

Created `./smt-sim-1.sled` in 15.588667ms
Created `./smt-sim-5.sled` in 16.102459ms
Created `./smt-sim-10.sled` in 12.913291ms
Created `./smt-sim-100.sled` in 18.115709ms
Created `./smt-sim-1K.sled` in 46.879792ms
Created `./smt-sim-10K.sled` in 444.898583ms
Created `./smt-sim-100K.sled` in 8.209993291s
Created `./smt-sim-1M.sled` in 1050.05839325s

sled DB dir size on macos:

> du -hs smt-sim-*
8.0K    smt-sim-1.sled
12K    smt-sim-10.sled
184K    smt-sim-100.sled
499M   smt-sim-100K.sled
37M    smt-sim-10K.sled
3.0M    smt-sim-1K.sled
5.3G    smt-sim-1M.sled
8.0K    smt-sim-5.sled


rocksdb DB dir creation times on macos:

Created `./smt-sim-1.rocksdb` in 9.938042ms
Created `./smt-sim-5.rocksdb` in 5.63625ms
Created `./smt-sim-10.rocksdb` in 3.875292ms
Created `./smt-sim-100.rocksdb` in 6.721583ms
Created `./smt-sim-1K.rocksdb` in 39.846333ms
Created `./smt-sim-10K.rocksdb` in 419.572375ms
Created `./smt-sim-100K.rocksdb` in 5.63792975s
Created `./smt-sim-1M.rocksdb` in 72.629013375s


rocksdb DB dir size on macos:

> du -hs smt-sim-*
60K    smt-sim-1.rocksdb
56K    smt-sim-10.rocksdb
132K    smt-sim-100.rocksdb
181M    smt-sim-100K.rocksdb
16M    smt-sim-10K.rocksdb
1.2M    smt-sim-1K.rocksdb
2.1G    smt-sim-1M.rocksdb
56K    smt-sim-5.rocksdb


# Jay (Batched)

## Machine: Windows, 24-core AMD 5900X, 32 GB RAM

Created `./db/smt-sim-1.sled` in 23.811ms
Created `./db/smt-sim-5.sled` in 14.8321ms
Created `./db/smt-sim-10.sled` in 15.3024ms
Created `./db/smt-sim-100.sled` in 13.1465ms
Created `./db/smt-sim-1K.sled` in 48.598ms
Created `./db/smt-sim-10K.sled` in 712.055ms
Created `./db/smt-sim-50K.sled` in 4.8962603s
Created `./db/smt-sim-100K.sled` in 10.6295349s

2.0K    ./db/smt-sim-1.sled
5.0K    ./db/smt-sim-5.sled
9.0K    ./db/smt-sim-10.sled
177K    ./db/smt-sim-100.sled
3.0M    ./db/smt-sim-1K.sled
44M     ./db/smt-sim-10K.sled
272M    ./db/smt-sim-50K.sled
585M    ./db/smt-sim-100K.sled


Created `./db/smt-sim-1.rocksdb` in 36.2248ms
Created `./db/smt-sim-5.rocksdb` in 34.0627ms
Created `./db/smt-sim-10.rocksdb` in 34.8857ms
Created `./db/smt-sim-100.rocksdb` in 34.3815ms
Created `./db/smt-sim-1K.rocksdb` in 44.5569ms
Created `./db/smt-sim-10K.rocksdb` in 207.8223ms
Created `./db/smt-sim-50K.rocksdb` in 1.4201617s
Created `./db/smt-sim-100K.rocksdb` in 3.3310485s

54K     ./db/smt-sim-1.rocksdb
50K     ./db/smt-sim-5.rocksdb
50K     ./db/smt-sim-10.rocksdb
114K    ./db/smt-sim-100.rocksdb
1.1M    ./db/smt-sim-1K.rocksdb
14M     ./db/smt-sim-10K.rocksdb
80M     ./db/smt-sim-50K.rocksdb
170M    ./db/smt-sim-100K.rocksdb


## Machine: macOS, 16-core M3 MAX (2023), 64 GB RAM

Created `./db/smt-sim-1.sled` in 30.865292ms
Created `./db/smt-sim-5.sled` in 21.206333ms
Created `./db/smt-sim-10.sled` in 13.619583ms
Created `./db/smt-sim-100.sled` in 14.676458ms
Created `./db/smt-sim-1K.sled` in 42.435291ms
Created `./db/smt-sim-10K.sled` in 455.511083ms
Created `./db/smt-sim-50K.sled` in 3.001970458s
Created `./db/smt-sim-100K.sled` in 7.497818s

8.0K    ./db/smt-sim-1.sled
8.0K    ./db/smt-sim-5.sled
12K     ./db/smt-sim-10.sled
176K    ./db/smt-sim-100.sled
3.0M    ./db/smt-sim-1K.sled
44M     ./db/smt-sim-10K.sled
273M    ./db/smt-sim-50K.sled
593M    ./db/smt-sim-100K.sled

Created `./db/smt-sim-1.rocksdb` in 3.483709ms
Created `./db/smt-sim-5.rocksdb` in 1.785083ms
Created `./db/smt-sim-10.rocksdb` in 1.616625ms
Created `./db/smt-sim-100.rocksdb` in 2.151167ms
Created `./db/smt-sim-1K.rocksdb` in 10.6365ms
Created `./db/smt-sim-10K.rocksdb` in 133.373667ms
Created `./db/smt-sim-50K.rocksdb` in 1.005048083s
Created `./db/smt-sim-100K.rocksdb` in 2.647476125s

60K     ./db/smt-sim-1.rocksdb
56K     ./db/smt-sim-5.rocksdb
56K     ./db/smt-sim-10.rocksdb
124K    ./db/smt-sim-100.rocksdb
1.1M    ./db/smt-sim-1K.rocksdb
14M     ./db/smt-sim-10K.rocksdb
80M     ./db/smt-sim-50K.rocksdb
177M    ./db/smt-sim-100K.rocksdb
