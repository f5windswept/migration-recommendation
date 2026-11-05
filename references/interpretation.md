# Evidence and sizing interpretation

## Evidence states

`incomplete` means missing, unsupported, or unparsable evidence—not zero utilization. `no_application_use_observed` is bounded by the captured configuration and counter history. `configured` is not proof of traffic. `historical_activity` is not a current rate. `configured_bypassed` is based on a static unconditional ASM-disable policy and available attached iRule checks; it is not deprovisioning.

The collector uses iHealth's UI endpoints, not a guaranteed stable public API. It discovers command links per QKView and records unavailable commands/schema changes. Supported output is best for classic BIG-IP TMOS captures. F5OS host, BIG-IP Next, VELOS chassis, vCMP host/guest, or other specialized captures may require additional collection; do not force them into a standalone LTM appliance model.

The static parser reads tmsh configuration; it never executes Tcl. It traces captured profile names/policies and direct non-LTM calls in attached iRules. Arbitrary `eval`, indirect calls, inherited/custom profile behavior, policy-driven virtual chaining, or external dependencies may need manual review. Missing script bodies preclude an unconditional assertion of module bypass. Module checks do not replace a feature-complete migration validation.

## Statistics

- Percentile: nearest rank over finite, nonnegative valid samples. Invalid/missing/negative/bool values are excluded and counted. No zero filling.
- All graph labels, expressions, time bounds, sample counts, and interval metadata are retained. Graph timestamp timezone is not guessed from the analyst's workstation.
- Combined outbound: time-aligned client-side plus server-side TMM output; label/unit/interval checks are required. It is a screening metric, not verified VE licensing accounting. Never sum all ingress and egress counters indiscriminately.
- TLS inconsistency heuristic: at least 100 reported SSL TPS and more than 10× contemporaneous new client CPS. This flags investigation, not a proven reset or confirmed demand. Other suspicious series can still require manual analysis.
- Source CPU and platform memory do not map one-to-one to VE vCPUs or tenant resources. Separate TMM, host, analysis-plane, and total-memory denominators.
- A growth multiplier is only applied when explicitly provided. A benchmark margin is not a performance guarantee with simultaneous features or unknown bursts.

## Sizing and deployment

Use whole-tenant resources for the proposed workload, matching per-peer resources. On r2000/r4000, the documented default RAM is `3 GiB × tenant CPUs`; on r5000 and above, the documented formula is `3.5 GiB × tenant vCPUs + 0.5 GiB`. Confirm the chosen F5OS/image's allowed allocations. Platform memory is larger than tenant memory; control-plane and platform reservations matter. r2000/r4000 do not provide the FPGA architecture of r5000/r10000. Datasheet figures already incorporate rSeries virtualization overhead.

Compare required port count, speed, optics, LAGs, HA links, and site placement independently from observed throughput. A four-member 10GbE trunk does not establish a 40Gbps VE throughput requirement. A surviving member must carry the defined failover workload; active/standby entitlements do not add together. Multiple tenants cannot provide appliance-failure redundancy if both HA members share one chassis/appliance.

For VE, validate current SKU limits, features, vCPU ceiling, packet rate, CPU/RAM reservations, hypervisor support, NUMA/NIC layout, and TLS performance. A licensed bandwidth limit is not a TLS TPS guarantee. Follow current hypervisor guidance; VMware automatic live migration of a busy BIG-IP VE is not a substitute for controlled BIG-IP failover. Compare reserved host/hypervisor/storage/support costs with appliance/optics/power costs before making TCO claims.

## Lifecycle and migration

Extract each new device's lifecycle dates; never carry another customer's January/date assumptions forward. EoSS, EoSD, EoNSS, software EoTS, and contract/RMA dates differ. Confirm current authoritative milestones and the target release's remaining lifecycle.

Obtain fresh UCS backups for migration. Confirm EHF fixes in the target release; newer version numbers alone do not prove fix equivalence. Recreate F5OS interfaces/LAGs/VLAN exposure and validate tenant networking. Current F5 guidance favors native `platform-migrate` for newer TMOS versions; `validate` is documented beginning with 21.1. Journeys compatibility varies. Recheck current guidance at use time. rSeries migration does not require BIG-IP Next.

## Sources

- [rSeries sizing](https://clouddocs.f5.com/training/community/rseries-training/html/rseries_performance_and_sizing.html)
- [rSeries HA](https://clouddocs.f5.com/training/community/rseries-training/html/rseries_high_availability.html)
- [rSeries migration](https://clouddocs.f5.com/training/community/rseries-training/html/migration_to_rseries.html)
- [UCS workflow](https://techdocs.f5.com/en-us/bigip-21-1-0/big-ip-system-migrating-devices-and-configurations-between-different-platforms/ucs-migration-workflow-for-f5os-big-ip-platforms.html)
- [VE licensing limits K14810](https://my.f5.com/manage/s/article/K14810)
- [VE supported platforms](https://clouddocs.f5.com/cloud/public/v1/matrix.html)
- [VE VMware deployment](https://clouddocs.f5.com/cloud/public/v1/vmware/vmware_setup.html)
- [VE hypervisor practices](https://clouddocs.f5.com/cloud/public/v1/vmware/optimize.html)

`platforms.json` is a versioned baseline derived from the cited March 2025 datasheet and sizing guide, last reviewed November 5, 2026. It is not an exhaustive catalog or a live pricing/lifecycle feed. Its VE SKU limits are explicitly unverified. Update source dates and catalog version when revising values; do not silently turn a historical baseline into a current claim.
