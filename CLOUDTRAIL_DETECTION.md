# CloudTrail detection

`detect_events` consumes CloudTrail record dictionaries and produces deterministic investigation signals. The rules recognize successful policy attachment/inline-policy/version changes, trust changes and key creation (MITRE ATT&CK T1098 / T1098.001); cross-account AssumeRole observations and three access denials by the same identity within five minutes are mapped to T1078.004 as investigation context, not proof of that technique.

Records are deduplicated by eventID (stable content hash if absent). Failed policy changes are not reported as successful modifications. Denial correlation requires parseable timestamps. Each alert preserves source event evidence and IDs. Alerts correlate with matching identity findings and graph paths. Synthetic fixtures use reserved documentation IP addresses and are labeled synthetic.

This is not behavioral anomaly detection. There is no learned normality, geolocation, stolen-credential verdict, or assertion that a rare operation is malicious. STS assumed-role session ARNs are not yet mapped to canonical IAM role ARNs; this can reduce correlation recall. CloudTrail event history does not include every data event, and absence of evidence is not absence of activity. Authorization for importing event metadata is required; the product never retrieves access-key secrets.
