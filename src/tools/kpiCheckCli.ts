import { getKpiSnapshot } from "../api/kpi";

interface Thresholds {
  warnStatusUnavailableRate: number;
  critStatusUnavailableRate: number;
  warnResolverInconsistentTotal: number;
  critResolverInconsistentTotal: number;
  failOnWarning: boolean;
}

function getThresholds(): Thresholds {
  return {
    warnStatusUnavailableRate: Number(process.env.KPI_WARN_STATUS_UNAVAILABLE_RATE ?? 0.05),
    critStatusUnavailableRate: Number(process.env.KPI_CRIT_STATUS_UNAVAILABLE_RATE ?? 0.2),
    warnResolverInconsistentTotal: Number(process.env.KPI_WARN_RESOLVER_INCONSISTENT_TOTAL ?? 5),
    critResolverInconsistentTotal: Number(process.env.KPI_CRIT_RESOLVER_INCONSISTENT_TOTAL ?? 20),
    failOnWarning: process.env.KPI_FAIL_ON_WARNING === "1",
  };
}

function run(): void {
  const kpi = getKpiSnapshot();
  const t = getThresholds();

  const statusRate = Number(kpi.deny_status_source_unavailable_rate ?? 0);
  const cacheHits = Number(kpi.revoked_cache_hit_total ?? 0);
  const cacheStores = Number(kpi.revoked_cache_store_total ?? 0);
  const revokedTotal = Number(kpi.deny_credential_revoked_total ?? 0);
  const reauthInvalidTotal = Number(kpi.deny_reauth_proof_invalid_total ?? 0);
  const resolverQuorumFailures = Number(kpi.resolver_quorum_failures_total ?? 0);
  const resolverInconsistent = Number(kpi.resolver_inconsistent_responses_total ?? 0);

  const issues: string[] = [];

  if (statusRate > t.critStatusUnavailableRate) {
    issues.push(`CRITICAL: deny_status_source_unavailable_rate=${statusRate} > ${t.critStatusUnavailableRate}`);
  } else if (statusRate > t.warnStatusUnavailableRate) {
    issues.push(`WARNING: deny_status_source_unavailable_rate=${statusRate} > ${t.warnStatusUnavailableRate}`);
  }

  if (cacheStores > 0 && cacheHits > cacheStores * 10) {
    issues.push(`WARNING: revoked cache hit/store skew high (${cacheHits}/${cacheStores})`);
  }

  if (resolverInconsistent > t.critResolverInconsistentTotal) {
    issues.push(
      `CRITICAL: resolver_inconsistent_responses_total=${resolverInconsistent} > ${t.critResolverInconsistentTotal}`
    );
  } else if (resolverInconsistent > t.warnResolverInconsistentTotal) {
    issues.push(
      `WARNING: resolver_inconsistent_responses_total=${resolverInconsistent} > ${t.warnResolverInconsistentTotal}`
    );
  }

  const output = {
    checkedAt: new Date().toISOString(),
    thresholds: t,
    kpi: {
      deny_status_source_unavailable_rate: statusRate,
      revoked_cache_hit_total: cacheHits,
      revoked_cache_store_total: cacheStores,
      deny_credential_revoked_total: revokedTotal,
      deny_reauth_proof_invalid_total: reauthInvalidTotal,
      resolver_quorum_failures_total: resolverQuorumFailures,
      resolver_inconsistent_responses_total: resolverInconsistent,
    },
    issues,
    ok: issues.length === 0,
  };

  console.log(JSON.stringify(output, null, 2));

  if (issues.some((i) => i.startsWith("CRITICAL"))) {
    process.exitCode = 2;
    return;
  }

  if (issues.length > 0 && t.failOnWarning) {
    process.exitCode = 1;
  }
}

run();
