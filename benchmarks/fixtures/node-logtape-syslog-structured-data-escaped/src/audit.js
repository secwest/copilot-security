import { configure, dispose, getLogger } from "@logtape/logtape";
import { getSyslogSink } from "@logtape/syslog";

await configure({
  sinks: {
    security: getSyslogSink({
      hostname: "127.0.0.1",
      port: Number(process.env.COPILOT_SECURITY_SYSLOG_PORT),
      protocol: "udp",
      includeStructuredData: true,
      appName: "cps-benchmark",
      syslogHostname: "localhost",
      processId: "benchmark",
    }),
  },
  loggers: [
    { category: ["audit"], sinks: ["security"], lowestLevel: "info" },
    { category: ["logtape", "meta"], sinks: [], lowestLevel: null },
  ],
});
const auditLogger = getLogger(["audit"]);
export function auditRequest(request) {
  auditLogger.info("request audited", { audit: request.body.audit });
}
export { dispose as disposeAuditLogging };
