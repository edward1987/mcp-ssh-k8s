/** Pasted keys often arrive with CRLF line endings and no trailing newline; OpenSSH-format keys need both fixed. */
export const normalizeKey = (k: string) => k.split("\r\n").join("\n").trim() + "\n";
