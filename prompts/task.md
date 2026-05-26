# Task template for tunnel config generation

Generate a novel tunnel protocol configuration that evades all M1–M8 detection metrics.

## Constraints for this run
- Preferred SNI / camouflage domain: **{domain}**
- Preferred listening port: **{port}**
- Handshake strategy hint: **{handshake_hint}**
- Padding focus: **{padding_hint}**
- Run index: {run_index} of {total_runs}  (use this to vary parameters across runs)

## Requirements
R1. `transport.type` MUST be `tls` (raw-tcp/udp is immediately detectable by M3 entropy analysis).
R2. `transport.tls.fingerprint` MUST be `chrome-120`, `firefox-120`, or `safari-17` (not `go`).
R3. `transport.tls.sni` MUST be non-empty (empty SNI triggers Suricata rule 9000002).
R4. `fallback.enabled` MUST be `true` with a real HTTPS target (required for M8).
R5. `padding.mode` MUST NOT be `fixed` (uniform frame sizes → instant M6 FAIL).
R6. For automated testing: use `handshake.type: tls-token` OR `noise` with pattern `NNpsk2`/`NNpsk0`/`NN`.
    Leave `psk` fields empty — the evaluator injects real key material.
    For noise: set `local_key: "generate"`.
R7. Choose `timing.mode: none` unless you have a specific hypothesis about timing obfuscation.

## Scoring context
This config will be tested against:
- nDPI deep-packet inspection
- Suricata IDS with Emerging Threats Open ruleset
- Zeek JA3 fingerprinting + Shannon entropy analysis
- XGBoost ML classifier (trained on flow statistics)
- Active TCP probing (5 probe types)

Think step by step: transport → handshake → padding → fallback.
Then fill in the `output` tool with your GenerationResult.
