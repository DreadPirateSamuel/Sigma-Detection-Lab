# Third-party sources

- EVTX-ATTACK-SAMPLES, https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES,
  GPL-3.0. Used as pinned recorded lab simulation data. Only public source
  filenames and derived counts/features are included; raw EVTX is excluded.
- evtx-baseline, https://github.com/NextronSystems/evtx-baseline,
  Apache-2.0. Used as release v0.8.5 client baseline data. Raw archives/logs
  are excluded; downloads retain upstream provenance and hash checks.
- Sigma/pySigma and the Elasticsearch backend supply conversion libraries;
  their implementation is not vendored here. Dependencies retain their
  own licenses. Generic rule format: https://sigmahq.io/.
- Sysmon (Microsoft Sysinternals) collected the live-host events, configured
  with the sysmon-modular default configuration,
  https://github.com/olafhartong/sysmon-modular. Neither is redistributed;
  both retain their own terms/licenses.
- MITRE ATT&CK supplies technique names/identifiers referenced by the rules:
  https://attack.mitre.org/. This project is not endorsed by MITRE.
- Microsoft documentation supplies Windows event/process/task semantics;
  Elastic supplies the installed Winlogbeat pipelines and SIEM software.
  Those products and documentation retain their own terms/licenses and
  are not redistributed in this source package.

The project's MIT license applies to original project source/docs/rules,
not external datasets or software.
