import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// Docs for tresor - one OIDC login, role-based secrets for DuckDB. Mirrors the
// mssql-extension and mssql-ducklake sites and the org site (hugr-lab.github.io)
// so they share look and feel; published by this repo's Pages workflow to
// https://hugr-lab.github.io/tresor/ (and, with DOCS_TARGET=ionos, to hugr-lab.com/docs/tresor/). The protocol page is the normative
// specification of duckdb-secrets/1 - a secrets service in any language
// implements that page.

// The same docs are built twice: for GitHub Pages (default) and for hugr-lab.com on IONOS (DOCS_TARGET=ionos).
// The IONOS copy must request nothing from another server (the site's CSP and its Datenschutz): links only.
const ionos = process.env.DOCS_TARGET === 'ionos';
const site = ionos
  ? {url: 'https://hugr-lab.com', baseUrl: '/docs/tresor/', home: 'https://hugr-lab.com/', impressum: 'https://hugr-lab.com/impressum/', datenschutz: 'https://hugr-lab.com/datenschutz/'}
  : {url: 'https://hugr-lab.github.io', baseUrl: '/tresor/', home: 'https://hugr-lab.github.io/', impressum: 'https://hugr-lab.github.io/impressum/', datenschutz: 'https://hugr-lab.github.io/datenschutz/'};
// While the hugr-lab.com copy exists (DOCS_IONOS on), pages.yml sets DOCS_CANONICAL for
// the GitHub Pages build: its pages then name the hugr-lab.com copy as canonical
// (src/theme/SiteMetadata) and it has no sitemap of its own.
const canonicalBase = ionos ? '' : process.env.DOCS_CANONICAL ?? '';

const config: Config = {
  title: 'tresor',
  tagline: 'One OIDC login, role-based secrets for DuckDB - attach your company\'s secrets service.',
  favicon: 'img/tresor-favicon.svg',

  url: site.url,
  baseUrl: site.baseUrl,
  baseUrlIssueBanner: false,
  trailingSlash: true,
  customFields: {docsTarget: ionos ? 'ionos' : 'github', canonicalBase},

  organizationName: 'hugr-lab',
  projectName: 'tresor',

  // 'throw', not 'warn': docs-build.yml is the PR gate for website/, and a
  // gate that exits 0 on a broken link does not gate anything.
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Docs ARE the site: /tresor/<page>/
          routeBasePath: '/',
          // Versions are made at DEPLOY time from the release tags (pages.yml),
          // so nothing is committed for them; the live docs/ tree publishes as
          // "Next" once a release exists.
          editUrl: 'https://github.com/hugr-lab/tresor/tree/main/website/',
          showLastUpdateTime: true,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
        sitemap: canonicalBase ? false : undefined,
      } satisfies Preset.Options,
    ],
  ],

  themes: ['@docusaurus/theme-mermaid'],

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  headTags: [
    // the tresor mark (hugr's ring, a keyhole): PNGs beside the SVG favicon, for browsers and home screens
    {tagName: 'link', attributes: {rel: 'icon', type: 'image/png', sizes: '32x32', href: `${site.baseUrl}img/tresor-favicon-32.png`}},
    {tagName: 'link', attributes: {rel: 'apple-touch-icon', sizes: '192x192', href: `${site.baseUrl}img/tresor-favicon-192.png`}},
  ],

  themeConfig: {
    metadata: [
      {name: 'keywords', content: 'DuckDB, secrets, OIDC, SSO, Keycloak, Entra ID, Okta, delegation, extension'},
      {name: 'description', content: 'DuckDB extension that attaches a secrets service: one OIDC login, role-based access to secrets, delegation for servers.'},
    ],
    navbar: {
      title: 'tresor',
      logo: {
        alt: 'tresor',
        src: 'img/tresor-icon.svg',
        srcDark: 'img/tresor-icon-dark.svg',
        href: '/',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          to: '/protocol/',
          label: 'Protocol',
          position: 'left',
        },
        {
          href: site.home,
          label: 'Hugr Lab',
          position: 'right',
        },
        {
          href: 'https://github.com/hugr-lab/tresor',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    colorMode: {
      defaultMode: 'light',
      disableSwitch: true,
      respectPrefersColorScheme: false,
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Getting Started', to: '/getting-started/'},
            {label: 'Concepts', to: '/concepts/'},
            {label: 'Protocol', to: '/protocol/'},
            {label: 'Security model', to: '/security/'},
          ],
        },
        {
          title: 'Community',
          items: [
            {label: 'GitHub', href: 'https://github.com/hugr-lab/tresor'},
            {label: 'Issues', href: 'https://github.com/hugr-lab/tresor/issues'},
            {label: 'DuckDB Secrets Manager', href: 'https://duckdb.org/docs/stable/configuration/secrets_manager'},
          ],
        },
        {
          title: 'Hugr Lab',
          items: [
            {label: 'Main site', href: site.home},
            {label: 'DuckDB MSSQL Extension', href: 'https://hugr-lab.github.io/mssql-extension/'},
          ],
        },
        {
          title: 'Legal',
          items: [
            {label: 'Impressum', href: site.impressum},
            {label: 'Datenschutz', href: site.datenschutz},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Hugr Lab.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['sql', 'bash', 'json'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
