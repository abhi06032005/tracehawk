"use client";
export default function ErrorPage({reset}:{reset:()=>void}){
  return <div className="m-6 rounded-xl border border-red-200 bg-white p-6"><h1 className="text-xl font-semibold">This page could not load</h1><p className="mt-2 text-sm text-slate-600">Your saved sessions are still in the database. Retry this page or return to the recorder.</p><button onClick={reset} className="mt-4 rounded-lg bg-indigo-600 px-4 py-2 text-sm text-white">Retry page</button><a href="/" className="ml-4 text-sm text-indigo-700">Recorder home</a></div>;
}
