# PNova

As we know [the original Nova implementation](https://github.com/microsoft/Nova)  is based on R1CS. Our target is to implement a plonkish versioned NOVA, folding multiple Gate, Wiring, and Lookup instances into one respectively. Thereafter, we can feed the folded instances into the relaxed Plonk SNARK.

<br />

##  Intuition About Plonkish Nova
![Alt text](image-1.png)

<br />

## Details About Implementation

Before intensive coding we will give more comprehensive details as much as possible, including some attestation code:
- [Thinking in Folding Scheme: Cross Term in R1CS](https://hackmd.io/@70xfCGp1QViTYYJh3AMrQg/BJZPMjIfT)
- [Thinking in Folding Scheme: Cross Term in Plonk](https://hackmd.io/@70xfCGp1QViTYYJh3AMrQg/SkDf2nIzp)
- [Thinking in Folding Scheme: Cycle Curves](https://hackmd.io/@70xfCGp1QViTYYJh3AMrQg/r1bN8nLMp)
- [Relaxed Plonk Step by Step](https://hackmd.io/@70xfCGp1QViTYYJh3AMrQg/BkT0ayKmT)
- [Plonk From Scratch](https://hackmd.io/@70xfCGp1QViTYYJh3AMrQg/HJzwPUU7a)

<br />

## Roadmap

| Features                           | Status  |
| ---------------------------------- | :-----: |
| **Stage One**                      |         |
| Uncompressed Relaxed Plonk Backend | Ongoing |
| Uncompressed NIFS                  |  TODO   |
| Uncompressed Cycle-Curve Circuits  |  TODO   |
| **Stage Two**                      |         |
| Compressed Relaxed Plonk Backend   |  TODO   |
| compressed NIFS                    |  TODO   |
| Compressed Cycle-Curve Circuits    |  TODO   |
| **Stage Three**                    |         |
| Add PLookup Argument               |  TODO   |
| Add logUp Argument                 |  TODO   |
| **Stage Four**                     |         |
| Cycle-fold Delegated Circuit       |  TODO   |
| Improving logUp Argument with GKR  |  TODO   |
| GKR Based Permutation Check        |  TODO   |

<br />

## References
[1] NOVA: https://eprint.iacr.org/2021/370.pdf

[2] CycleFold: https://eprint.iacr.org/2023/1192.pdf

[3] Protostar: https://eprint.iacr.org/2023/620.pdf

[4] Multivariate lookup: https://eprint.iacr.org/2022/1530.pdf

[5] Cached quotients: https://eprint.iacr.org/2022/1763.pdf

[6] Improving logUp argument with GKR: https://eprint.iacr.org/2023/1284.pdf