# PNova

As we know [the original Nova implementation](https://github.com/microsoft/Nova)  is based on R1CS. Our target is to implement a plonkish versioned NOVA, folding multiple Gate, Wiring, and Lookup instances into one respectively. Thereafter, we can feed the folded instances into Plonk SNARK.

<br />

## Roadmap

| Features                          | Status  |
| --------------------------------- | :-----: |
| **Base Functionality**            |         |
| Plonkish(gate+wiring) NIFS        | Ongoing |
| Cycle-Curve Circuits              | Ongoing |
| Simplified Plonkish NOVA          | Ongoing |
| **Advanced Functionality**        |         |
| Halo2-Lookup Argument             | Ongoing |
| **Optimization**                  |         |
| Cycle-fold Delegated Circuit      | Ongoing |
| Protostar Compressed Verification | Ongoing |
| PLookup Argument                  | Ongoing |
| logUp Argument                    | Ongoing |
| Improving logUp Argument with GKR | Ongoing |

<br />

## References
[1] NOVA: https://eprint.iacr.org/2021/370.pdf

[2] CycleFold: https://eprint.iacr.org/2023/1192.pdf

[3] Protostar: https://eprint.iacr.org/2023/620.pdf

[4] Multivariate lookup: https://eprint.iacr.org/2022/1530.pdf

[5] Cached quotients: https://eprint.iacr.org/2022/1763.pdf

[6] Improving logUp argument with GKR: https://eprint.iacr.org/2023/1284.pdf