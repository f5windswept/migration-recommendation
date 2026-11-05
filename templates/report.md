# {{CUSTOMER}} — BIG-IP migration recommendation

Evidence run: `{{RUN_ID}}`

> Draft outline. The assistant must replace placeholders with evidence-backed analysis before presenting this as a recommendation.

## Executive recommendation

[Name the recommended platform(s), quantity, tenant/VM resources, module scope, and confidence. State any decision-changing unresolved evidence.]

## Current topology and workload

[Identify actual HA peers, active roles, snapshot dates, traffic groups, and sites where known. Show workload percentiles/maxima with sample intervals. Do not double-count replicated configuration or add standby capacity.]

## Module utilization and migration dependencies

[Separate licensed/provisioned/configured/attached/observed activity. Trace ASM enable/disable actions, distinguish Tcl iRules from ILX, and handle device-level DoS separately from firewall policies. Identify LAGs, route domains, certificates, iApps, EHF fixes, and any source features being removed.]

## rSeries versus VE

[Compare appropriate dated benchmarks, tenant allocations, required modules, networking, crypto, growth assumptions, and surviving-member load. Identify the specific supported VE host and license requirements. No automatic current SKU, TCO, or lifecycle claims.]

## Proposed configuration and sizing rationale

[Per-member resources, licensing scope, interfaces/optics, power, HA placement, and validation criteria. Clearly distinguish a test allocation from approved production sizing.]

## Migration plan and acceptance

[Fresh UCS backups; supported source/target image and EHF compatibility; platform-specific configuration migration; isolated staging; application and single-member load/failover tests; cutover and rollback; lifecycle deadline.]

## Assumptions, unresolved questions, and sources

[List only material unknowns, evidence gaps, and what would change the recommendation. Cite this run's QKViews/command evidence and current F5 references.]
