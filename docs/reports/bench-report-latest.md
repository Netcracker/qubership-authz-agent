# OPA Benchmark Report

Generated: 2026-04-13 07:18:22 UTC
Runs per scenario: 10

## Methodology

- **Tool**: `opa bench --format json --count 5`, with multiple independent invocations per scenario.
- **Best run selection**: from all invocations, the one with the lowest
  `histogram_timer_rego_query_eval_ns` 95th-percentile value is selected.
- **Deviation calculation**: `((worst_p95 - best_p95) / best_p95) * 100` — shows the spread
  between the best and worst run as a percentage.

### Benchmark groups

- **ols-single / ols-single-Nroles**: single-resource OLS authorization, varying the number of
  subject roles to isolate role-cardinality cost.
- **ols-bulk-N**: bulk OLS authorization with N resources in one request.
- **rls-condition-N-expression**: RLS with N `conditionAst` expressions (abstract AST evaluation,
  no predicate generation).
- **rls-predicate**: single RLS predicate generation (1 RSQL predicate, 1 token PIP).
- **rls-predicate-summary-N-predicates**: RLS with N independent predicate objects per
  resource-type/operation (measures predicate aggregation and substitution scaling).
- **rls-predicate-pips-N-token-pip / N-header-pip**: single RLS predicate with varying numbers
  of token-claim or header-derived PIP references (measures PIP resolution scaling).
- **rls-predicate-summary-10-predicates-3-token-pip**: combined stress scenario — 10 predicates
  and 3 token PIPs.
- **wildcard-all-single**: global wildcard access short-circuit (single resource).
- **wildcard-mixed-bulk**: mixed wildcard + exact OLS in one bulk request.

## Results

| Scenario | N (iterations) | p95 (µs) | mean (µs) | median (µs) | p99 (µs) | allocs/op | B/op | deviation % |
| ---------- | --------------- | ----------- | ----------- | ------------- | ---------- | ----------- | ------ | ------------- |
| ols-single | 1986 | 827 | 523 | 463 | 1573 | 3751 | 174037 | 17.4 |
| ols-single-10roles | 2138 | 936 | 566 | 508 | 1714 | 4105 | 187858 | 10.9 |
| ols-single-20roles | 1971 | 1051 | 644 | 576 | 1771 | 4477 | 206782 | 12.7 |
| ols-single-30roles | 1689 | 1121 | 665 | 595 | 1802 | 4839 | 219337 | 16.5 |
| ols-single-50roles | 1416 | 1305 | 741 | 667 | 1886 | 5568 | 250494 | 27.3 |
| ols-single-100roles | 1268 | 1659 | 991 | 892 | 2330 | 7379 | 331477 | 15.0 |
| ols-bulk-50 | 386 | 4152 | 2968 | 2783 | 5054 | 28392 | 1301489 | 13.6 |
| ols-bulk-100 | 189 | 7282 | 5472 | 5376 | 8111 | 53511 | 2454728 | 11.6 |
| ols-bulk-1000 | 25 | 62930 | 53114 | 53083 | 63360 | 516163 | 23445519 | 15.0 |
| | | | | | | | | |
| rls-condition-1-expression | 1142 | 1834 | 982 | 853 | 2533 | 6859 | 322968 | 16.3 |
| rls-condition-2-expression | 1064 | 1895 | 1002 | 910 | 2343 | 7575 | 352963 | 25.6 |
| rls-condition-3-expression | 933 | 1975 | 1084 | 961 | 2602 | 8291 | 382762 | 15.2 |
| rls-condition-5-expression | 817 | 2153 | 1230 | 1107 | 2889 | 9728 | 443051 | 5.5 |
| | | | | | | | | |
| rls-predicate | 1074 | 1814 | 964 | 846 | 2582 | 6741 | 319432 | 6.3 |
| rls-predicate-summary-2-predicates | 1178 | 1899 | 1017 | 908 | 2549 | 7211 | 334794 | 6.0 |
| rls-predicate-summary-3-predicates | 1142 | 1925 | 1038 | 939 | 2436 | 7638 | 350313 | 10.7 |
| rls-predicate-summary-4-predicates | 1131 | 1997 | 1087 | 969 | 2487 | 8058 | 364195 | 10.2 |
| rls-predicate-summary-5-predicates | 1060 | 2042 | 1166 | 1058 | 2572 | 8489 | 381294 | 12.4 |
| rls-predicate-summary-10-predicates | 760 | 2358 | 1379 | 1221 | 3262 | 10637 | 468673 | 13.8 |
| | | | | | | | | |
| rls-predicate-pips-1-token-pip | 1125 | 1912 | 1003 | 877 | 2550 | 6740 | 319283 | 10.6 |
| rls-predicate-pips-2-token-pip | 1024 | 1838 | 968 | 862 | 2332 | 7019 | 327792 | 16.9 |
| rls-predicate-pips-3-token-pip | 1014 | 1954 | 1046 | 920 | 2508 | 7293 | 337736 | 50.6 |
| rls-predicate-pips-1-header-pip | 1335 | 1861 | 1004 | 902 | 2464 | 6749 | 319498 | 29.5 |
| rls-predicate-pips-2-header-pip | 1046 | 1828 | 995 | 870 | 2619 | 7025 | 327408 | 14.4 |
| rls-predicate-pips-3-header-pip | 1122 | 1866 | 1035 | 906 | 2601 | 7296 | 336975 | 27.0 |
| rls-predicate-summary-10-predicates-3-token-pip | 666 | 2789 | 1667 | 1518 | 3424 | 12771 | 525551 | 11.8 |
| | | | | | | | | |
| wildcard-all-single | 1579 | 1242 | 685 | 594 | 1847 | 3559 | 164695 | 15.0 |
| wildcard-mixed-bulk | 244 | 6695 | 4357 | 4047 | 11299 | 29910 | 1343058 | 6.8 |
