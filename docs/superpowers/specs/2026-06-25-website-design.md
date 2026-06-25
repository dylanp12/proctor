# Proctor website + discovery — Design Spec

**Date:** 2026-06-25
**Status:** Draft → writing-plans
**Decisions (locked with Dylan):** Astro + Starlight; domain **proctorbench.dev** (not yet
registered — build domain-agnostic, point the CNAME later); full discovery push; $0 static
hosting; the site lives in the Proctor repo under `/site` on the `website` branch.

## Goal

A fast, SEO-strong static site — **landing + docs + one cornerstone post** — that (1) gives
operators/researchers/engineers arriving from outreach, GitHub, or search a credible first
impression, (2) ranks for the problem queries so people researching benchmark integrity *find*
Proctor, and (3) hosts the shareable technical writeup. Plus a discovery-asset checklist
(asciinema, OG image, repo SEO, Awesome-list PRs, cross-post plan). Proctor has no self-serve
product — the site sells *understanding + the standard*, not signups.

## Stack & hosting

- **Astro + Starlight** (Starlight powers `/docs`; a custom Astro page for `/`; an Astro
  content collection for `/blog`). Static output, ~100 Lighthouse, first-class SEO.
- **Hosting:** Cloudflare Pages (free) via git integration, building `site/` (`npm run build`,
  output `site/dist`). Custom domain `proctorbench.dev` attached when registered; until then the
  `*.pages.dev` subdomain. (Vercel is an equivalent fallback.)
- **Location:** `site/` in the Proctor repo (docs ↔ code together). `site/node_modules` and
  `site/dist` gitignored.

## Surfaces

### 1. Landing (`/`) — custom Astro page (not the Starlight default)
Sections, top to bottom:
- **Hero:** canonical line — "Proctor turns AI coding-agent benchmark runs into signed,
  independently verifiable integrity bundles" — + the answer-isolation subhead; CTAs: **GitHub**,
  **Docs**, **Read the writeup**; the `demo` CI badge.
- **The problem:** the cheating finding, correctly scoped — "in one removed Terminal-Bench 2
  submission, 415 of 429 successful runs were just `cat /tests`" — cited to DebugML + arXiv.
- **How it works (by construction):** masked mounts / empty netns / base-commit git + the
  seccomp audit; the `verdict.json` + `violations.jsonl` snippet.
- **Trust it:** the signed `bundle.json` + the four `verify-bundle` checks; the **live example
  bundle** (the `compromised` verdict + the `verify-bundle … --pubkey …` command), with the
  asciinema demo embedded.
- **Honest scope:** what it does NOT do (out-of-sandbox injection, grader-fooling) — kept
  prominent; it's a credibility asset.
- **Who it's for** + footer (links: GitHub, docs, post, MIT, the bundle spec).
- **Aesthetic:** dark, technical, monospace accents, one restrained accent color, the
  signed/`compromised` verdict as the recurring visual motif. Use the **frontend-design** skill
  during build for a distinctive, non-templated look (no stock SaaS-landing feel).

### 2. Docs (`/docs/*`) — Starlight, sourced from existing markdown
Reorganize the existing repo docs into a clean IA (adapt copies into
`site/src/content/docs/`; the repo `docs/*.md` stay the canonical source — note the light
duplication, acceptable for v1):
- **Overview** (from `why-proctor.md` intro) · **Quickstart** (README quickstart + `usage.md`)
  · **How it works** · **Bundle spec** (`bundle-spec.md`) · **Honest scope** · **FAQ**
  (`faq.md`) · **Roadmap** · **Example bundle** (`docs/examples/README.md`).
- Each doc page: correct title/description front-matter for SEO; code blocks with the repo's
  real commands.

### 3. Cornerstone post (`/blog/benchmark-cheating-dies-by-construction`)
Adapted from `launch-announcement.md` + the corpus result. Arc: the problem (cited) → why it's
a sandboxing not modeling failure → the by-construction mechanism → the corpus result → the
signed bundle + what a verifier concludes → honest scope → try it. This is the SEO + shareable
asset; written to rank and to be linked from outreach.

## SEO

- Per-page `<title>` + meta description + Open Graph/Twitter tags; canonical URLs at
  `https://proctorbench.dev/…`.
- `@astrojs/sitemap` → `sitemap.xml`; a `robots.txt`.
- JSON-LD: `SoftwareApplication` (the project, on `/`) + `TechArticle` (the post).
- Target queries: "AI benchmark cheating", "agent eval integrity", "verifiable / trustworthy
  agent benchmark", "sandbox AI coding-agent eval", "tamper-evident eval", "benchmark
  contamination cheating". Work these into titles, H1/H2s, and the post naturally.
- A custom **OG/social-preview image** (the "415/429 → blocked + signed" hook) for shares.
- Static + fast (Astro islands only where needed) for Core Web Vitals.

## Discovery assets (Part B — beyond the site)

- **asciinema demo:** record `proctor run` (agent reads masked `/oracle` → blocked + logged →
  `compromised`) then `verify-bundle` → OK. Embed on the landing + add to the README.
- **Repo SEO:** GitHub topics (`ai`, `evals`, `benchmarks`, `ai-agents`, `security`, `sandbox`,
  `rust`), a sharp repo description, a social-preview image, pin on the profile.
- **Awesome-list PRs:** draft PRs to relevant lists (awesome-llm / awesome-ai-agents /
  awesome-mlops / awesome-rust where it fits).
- **Cross-post plan** (for the cornerstone post, once live): Lobsters, r/MachineLearning, the
  eval/agent Discords + newsletters; a dev.to/Substack mirror with canonical pointing home.
  (Show HN is one-shot — do not repost.)

## Non-goals (v1)

No CMS, no signup/product surface, no heavy analytics (optional privacy-light Plausible later),
no i18n. Keep the repo `docs/*.md` as canonical; the site adapts them.

## Cost

$0 hosting (Cloudflare Pages free) + ~$9.99/yr domain. Within the $300/mo cap.
