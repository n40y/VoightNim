## =============================================================================
## signatures/http/monitoring.nim
##
## Signatures pour les outils de monitoring/observabilité exposés en HTTP.
## =============================================================================

import regex

import ../../fingerprint/types

proc getMonitoringSignatures*(): seq[MatchRule] =

  result = @[]

  result.add MatchRule(
    pattern: re2"(?i)X-Grafana-Version:\s*([\d.]+)",
    service: sidGrafana,
    versionGroup: 1,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)kbn-name",
    service: sidElastic,
    versionGroup: 0,
    confidence: 90,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Prometheus",
    service: sidPrometheus,
    versionGroup: 0,
    confidence: 85,
    headersOnly: false
  )
