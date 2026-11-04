package com.burpmax.scanner;

/**
 * Value object returned by each check module.
 */
public class CheckResult {
    public final String name;
    public final String severity;
    public final String description;
    public final String evidence;
    public final String remediation;
    public final String cwe;
    /** Optional: the request that was actually sent and the last response (active checks only). */
    public byte[] probeRequest;
    public byte[] probeResponse;

    /** Attach the traffic that produced this result. Returns this for chaining. */
    public CheckResult withTraffic(byte[] request, byte[] response) {
        this.probeRequest  = request;
        this.probeResponse = response;
        return this;
    }

    public CheckResult(String name, String severity, String description,
                       String evidence, String remediation, String cwe) {
        this.name        = name;
        this.severity    = severity;
        this.description = description;
        this.evidence    = evidence;
        this.remediation = remediation;
        this.cwe         = cwe;
    }
}
