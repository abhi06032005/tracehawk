import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number, decimals = 2) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function getSeverityBadge(severity: string) {
  switch (severity) {
    case "CRITICAL":
      return "bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/40 dark:text-rose-400 dark:border-rose-800";
    case "HIGH":
      return "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-800";
    case "MEDIUM":
      return "bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-950/40 dark:text-yellow-400 dark:border-yellow-800";
    case "LOW":
      return "bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/40 dark:text-sky-400 dark:border-sky-800";
    case "INFO":
    default:
      return "bg-slate-50 text-slate-700 border-slate-200 dark:bg-slate-900 dark:text-slate-400 dark:border-slate-800";
  }
}

export function getStatusBadge(status: string) {
  switch (status) {
    case "RECORDING":
      return "bg-emerald-50 text-emerald-700 border-emerald-200 animate-pulse";
    case "PAUSED":
      return "bg-amber-50 text-amber-700 border-amber-200";
    case "ANALYZED":
      return "bg-indigo-50 text-indigo-700 border-indigo-200";
    case "STOPPED":
    default:
      return "bg-slate-100 text-slate-700 border-slate-200";
  }
}

export function getVerificationBadge(status: string) {
  switch (status) {
    case "VERIFIED":
      return "bg-rose-100 text-rose-800 border-rose-300 font-bold";
    case "REJECTED":
      return "bg-slate-100 text-slate-600 border-slate-300 line-through";
    case "NEEDS_VERIFICATION":
      return "bg-amber-50 text-amber-800 border-amber-300 font-semibold";
    case "HYPOTHESIS":
    default:
      return "bg-indigo-50 text-indigo-700 border-indigo-200";
  }
}
