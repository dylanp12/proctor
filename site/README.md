# Proctor website (`proctorbench.dev`)

Astro + Starlight static site: a custom landing (`/`), docs (`/docs/*`, sourced from the repo's
markdown), and the cornerstone post (`/blog/*`). Builds to `site/dist`.

## Local development

```sh
cd site
npm install
npm run dev        # http://localhost:4321
npm run build      # static output -> site/dist
npm run preview    # serve the built site
```

## Deploy — Cloudflare Pages (free)

The site is **domain-agnostic**: it builds and serves on the `*.pages.dev` subdomain today; the
custom domain is attached when `proctorbench.dev` is registered. The canonical URL in
`astro.config.mjs` (`site: 'https://proctorbench.dev'`) is already set, so sitemap/canonical tags
are correct the moment the domain points here.

1. Cloudflare dashboard → **Workers & Pages → Create → Pages → Connect to Git** → the
   `dylanp12/proctor` repo.
2. Build settings:
   - **Production branch:** `main`
   - **Framework preset:** Astro
   - **Build command:** `npm run build`
   - **Build output directory:** `dist`
   - **Root directory:** `site`
3. Deploy → live at `https://<project>.pages.dev`.

### Attach the custom domain (after registering `proctorbench.dev`)

4. Pages project → **Custom domains → Set up a domain** → `proctorbench.dev` (and `www`).
5. If the domain's DNS is on Cloudflare, the records are added automatically; otherwise add the
   shown `CNAME`. HTTPS is provisioned automatically. No `astro.config` change needed.

> Vercel is an equivalent fallback: import the repo, set **Root Directory** to `site`; Astro is
> auto-detected.
