LuckyPepe Core
===============

https://luckypepe.org

What is LuckyPepe?
------------------

LuckyPepe (LPEPE) is a CPU-friendly Proof-of-Work cryptocurrency with random block rewards and no supply cap.

### Specifications

| Parameter | Value |
|-----------|-------|
| Algorithm | YescryptR32 |
| Block Time | 60 seconds |
| P2P Port | 9777 |
| RPC Port | 9778 |
| Address Prefix | lpep (bech32) |
| Decimals | 4 |
| Maturity | 100 blocks |
| Difficulty Retarget | Every 1440 blocks (~1 day) |
| Dev Fund | 7% per block |
| SegWit | Active from block 1 |
| Taproot | Active from block 1 |

### Block Rewards (Random)

| Stage | Block Height | Reward Range (LPEPE) |
|-------|-------------|---------------------|
| 1 | 0 - 262,800 | 1,000,000 - 3,000,000 |
| 2 | 262,801 - 525,600 | 500,000 - 1,500,000 |
| 3 | 525,601 - 788,400 | 250,000 - 750,000 |
| 4 | 788,401 - 1,051,200 | 125,000 - 375,000 |
| 5 | 1,051,201+ | 25,000 - 75,000 |

Block rewards are determined by the previous block hash, providing fair and unpredictable distribution with no total supply limit.

Building
--------

### Linux

```bash
./autogen.sh
./configure --without-gui --disable-tests --disable-bench
make -j$(nproc)
```

### Windows (Cross-compile)

```bash
cd depends
make HOST=x86_64-w64-mingw32
cd ..
CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/
make
```

See `doc/build-*.md` for detailed build instructions.

Resources
---------

- **Website**: https://luckypepe.org
- **Explorer**: https://explorer.luckypepe.org
- **Mining Pool**: https://pool.luckypepe.org

License
-------

LuckyPepe Core is released under the terms of the MIT license. See [COPYING](COPYING) for more information.
