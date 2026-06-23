+++
title = "sleep"
chapter = false
weight = 100
hidden = false
+++

## Summary

Changes the agent's beacon interval and jitter percentage at runtime without redeploying.

- **Platform**: Windows / Linux / macOS
- **Needs Admin**: No
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### seconds
- Description: Sleep interval in seconds between check-ins
- Required: Yes

#### jitter *(optional)*
- Description: Jitter percentage (0–100). Applied symmetrically: `interval ± (interval × jitter / 100)`
- Required: No
- Default: 0 (no jitter)

## Usage

```
sleep 60
sleep 30 20
sleep 300 10
```

## Notes

- Jitter is symmetric: `sleep 60 20` results in a random interval between 48s and 72s per cycle.
- Changes take effect on the next beacon cycle.
- Increase sleep + jitter during off-hours to reduce detection surface.

---

## Resumo em Português (PT-BR)

Altera o intervalo de beacon e o jitter do agente em runtime. O jitter é aplicado simetricamente: `sleep 60 20` → intervalo varia entre 48s e 72s por ciclo. A mudança entra em vigor no próximo ciclo de beacon.

Exemplo para operação discreta em horário comercial: `sleep 300 25`
