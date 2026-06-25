// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
	site: 'https://proctorbench.dev',
	integrations: [
		starlight({
			title: 'Proctor',
			description:
				'Turn AI coding-agent benchmark runs into signed, independently verifiable integrity bundles.',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/dylanp12/proctor' },
			],
			customCss: ['./src/styles/custom.css'],
			sidebar: [{ label: 'Documentation', items: [{ autogenerate: { directory: 'docs' } }] }],
		}),
		sitemap(),
	],
});
