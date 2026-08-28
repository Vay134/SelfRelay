import {
    DEFAULT_PROBE_TIMEOUT_MS,
    formatProbeLog,
    runAvailabilityProbe,
    type ProbeResult,
} from './probe';

export interface AvailabilityProbeEnvironment {
    AVAILABILITY_PROBE_URL?: string;
    AVAILABILITY_PROBE_TOKEN?: string;
    AVAILABILITY_PROBE_TIMEOUT_MS?: string;
}

export interface ScheduledController {
    cron: string;
    scheduledTime: number;
}

export interface ExecutionContext {
    waitUntil(promise: Promise<unknown>): void;
}

function configuredTimeout(environment: AvailabilityProbeEnvironment): number {
    const configured = Number(environment.AVAILABILITY_PROBE_TIMEOUT_MS);
    return Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_PROBE_TIMEOUT_MS;
}

function logResult(result: ProbeResult): void {
    // Keep logs structured and allowlisted. Never include env values or error
    // text because an endpoint or exception may contain sensitive material.
    console.log(JSON.stringify(formatProbeLog(result)));
}

export async function runScheduledProbe(
    environment: AvailabilityProbeEnvironment,
): Promise<ProbeResult> {
    const result = await runAvailabilityProbe({
        endpoint: environment.AVAILABILITY_PROBE_URL,
        token: environment.AVAILABILITY_PROBE_TOKEN,
        timeoutMs: configuredTimeout(environment),
    });
    logResult(result);
    return result;
}

export async function scheduled(
    _controller: ScheduledController,
    environment: AvailabilityProbeEnvironment,
    context: ExecutionContext,
): Promise<void> {
    const probe = runScheduledProbe(environment);
    context.waitUntil(probe);
    await probe;
}

export { formatProbeLog, runAvailabilityProbe } from './probe';
export type { ProbeConfig, ProbeDependencies, ProbeFailureReason, ProbeResult } from './probe';

export default { scheduled };
