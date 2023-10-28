# PNova

As we know [the original Nova implementation](https://github.com/microsoft/Nova)  is based on R1CS. Our target is to implement a plonkish versioned NOVA, folding multiple Gate, Wiring, and Lookup instances into one respectively. Thereafter, we can feed the folded instances into the relaxed Plonk SNARK.

<br />

## Details About Implementation

Before intensive coding we will give more comprehensive details as much as possible, including some attestation code:
- [Thinking in Folding Scheme: Cross Term in R1CS](https://hackmd.io/@70xfCGp1QViTYYJh3AMrQg/BJZPMjIfT)
- [Thinking in Folding Scheme: Cross Term in Plonk](https://hackmd.io/@70xfCGp1QViTYYJh3AMrQg/SkDf2nIzp)
- [Thinking in Folding Scheme: Cycle Curves](https://hackmd.io/@70xfCGp1QViTYYJh3AMrQg/r1bN8nLMp)

<br />

## Roadmap

| Features                           | Status  |
| ---------------------------------- | :-----: |
| **Stage One**                      |         |
| Uncompressed Relaxed Plonk Backend | Ongoing |
| Plonkish(gate+wiring) NIFS         |  TODO   |
| Cycle-Curve Circuits               |  TODO   |
| Uncompressed Plonkish Nova         |  TODO   |
| **Stage Two**                      |         |
| Compressed Relaxed Plonk Backend   |  TODO   |
| Compressed Plonkish NOVA           |  TODO   |
| **Stage Three**                    |         |
| Halo2-Lookup Argument              |  TODO   |
| PLookup Argument                   |  TODO   |
| **Stage Four**                     |         |
| GKR Based Permutation Check        |  TODO   |
| Cycle-fold Delegated Circuit       |  TODO   |
| logUp Argument                     |  TODO   |
| Improving logUp Argument with GKR  |  TODO   |

<br />

## References
[1] NOVA: https://eprint.iacr.org/2021/370.pdf

[2] CycleFold: https://eprint.iacr.org/2023/1192.pdf

[3] Protostar: https://eprint.iacr.org/2023/620.pdf

[4] Multivariate lookup: https://eprint.iacr.org/2022/1530.pdf

[5] Cached quotients: https://eprint.iacr.org/2022/1763.pdf

[6] Improving logUp argument with GKR: https://eprint.iacr.org/2023/1284.pdf