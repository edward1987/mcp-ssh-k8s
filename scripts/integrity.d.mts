export function createManifest(root: string, signingKey?: string): void;
export function verifyIntegrity(root: string, baseline?: string): boolean;
export const INTEGRITY_EXIT_CODE: number;
export function incidentPath(root: string): string;
export function recordIntegrityIncident(root: string, reason: string): void;
