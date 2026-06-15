import type { MDXComponents } from "mdx/types";
import type { ReactNode } from "react";
import { DocLink } from "@/components/DocLink";

// This file maps Markdown/MDX output to Tailwind-styled React components.
// It is REQUIRED by @next/mdx in the App Router and is applied to every .mdx
// file globally. Named components defined here (e.g. <Callout>) are available
// inside any .mdx page without an import.

type CalloutProps = {
  type?: "info" | "warning" | "danger" | "success";
  title?: string;
  children: ReactNode;
};

const calloutStyles: Record<NonNullable<CalloutProps["type"]>, string> = {
  info: "border-blue-500/40 bg-blue-500/[0.06]",
  warning: "border-amber-500/50 bg-amber-500/[0.07]",
  danger: "border-red-500/50 bg-red-500/[0.07]",
  success: "border-emerald-500/50 bg-emerald-500/[0.06]",
};

const calloutIcon: Record<NonNullable<CalloutProps["type"]>, string> = {
  info: "i",
  warning: "!",
  danger: "!",
  success: "✓",
};

export function Callout({ type = "info", title, children }: CalloutProps) {
  return (
    <div className={`my-6 rounded-lg border-l-4 border px-4 py-3 ${calloutStyles[type]}`}>
      {title ? (
        <p className="mb-1 flex items-center gap-2 font-semibold">
          <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-foreground/10 text-xs font-bold">
            {calloutIcon[type]}
          </span>
          {title}
        </p>
      ) : null}
      <div className="[&>p:first-child]:mt-0 [&>p:last-child]:mb-0 text-sm leading-7 text-foreground/90">
        {children}
      </div>
    </div>
  );
}

const components: MDXComponents = {
  h1: (props) => (
    <h1
      className="scroll-mt-24 text-3xl font-bold tracking-tight text-foreground sm:text-4xl"
      {...props}
    />
  ),
  h2: (props) => (
    <h2
      className="scroll-mt-24 mt-12 mb-4 border-b border-border pb-2 text-2xl font-semibold tracking-tight text-foreground"
      {...props}
    />
  ),
  h3: (props) => (
    <h3 className="scroll-mt-24 mt-8 mb-3 text-xl font-semibold text-foreground" {...props} />
  ),
  h4: (props) => (
    <h4 className="scroll-mt-24 mt-6 mb-2 text-base font-semibold text-foreground" {...props} />
  ),
  p: (props) => <p className="my-4 leading-7 text-foreground/90" {...props} />,
  a: DocLink,
  ul: (props) => <ul className="my-4 ml-6 list-disc space-y-2 marker:text-muted-foreground" {...props} />,
  ol: (props) => <ol className="my-4 ml-6 list-decimal space-y-2 marker:text-muted-foreground" {...props} />,
  li: (props) => <li className="leading-7 text-foreground/90" {...props} />,
  blockquote: (props) => (
    <blockquote className="my-5 border-l-2 border-border pl-4 italic text-muted-foreground" {...props} />
  ),
  hr: () => <hr className="my-10 border-border" />,
  strong: (props) => <strong className="font-semibold text-foreground" {...props} />,
  code: (props) => (
    <code
      className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.85em] text-foreground"
      {...props}
    />
  ),
  pre: (props) => (
    <pre
      className="my-5 overflow-x-auto rounded-lg border border-border bg-muted p-4 text-sm leading-relaxed [&_code]:bg-transparent [&_code]:p-0 [&_code]:text-foreground/90"
      {...props}
    />
  ),
  table: (props) => (
    <div className="my-6 overflow-x-auto rounded-lg border border-border">
      <table className="w-full border-collapse text-sm" {...props} />
    </div>
  ),
  thead: (props) => <thead className="bg-muted" {...props} />,
  th: (props) => (
    <th className="border-b border-border px-3 py-2 text-left font-semibold text-foreground" {...props} />
  ),
  td: (props) => (
    <td className="border-b border-border px-3 py-2 align-top text-foreground/90" {...props} />
  ),
  Callout,
};

export function useMDXComponents(incoming: MDXComponents = {}): MDXComponents {
  return { ...components, ...incoming };
}
