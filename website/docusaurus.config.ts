import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// Docs for tresor - one OIDC login, role-based secrets for DuckDB. Mirrors the
// mssql-extension and mssql-ducklake sites and the org site (hugr-lab.github.io)
// so they share look and feel; published by this repo's Pages workflow to
// https://hugr-lab.github.io/tresor/. The protocol page is the normative
// specification of duckdb-secrets/1 - a secrets service in any language
// implements that page.

const config: Config = {
  title: 'tresor',
  tagline: 'One OIDC login, role-based secrets for DuckDB - attach your company\'s secrets service.',
  favicon: 'img/favicon.ico',

  url: 'https://hugr-lab.github.io',
  baseUrl: '/tresor/',
  trailingSlash: true,

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

  themeConfig: {
    metadata: [
      {name: 'keywords', content: 'DuckDB, secrets, OIDC, SSO, Keycloak, Entra ID, Okta, delegation, extension'},
      {name: 'description', content: 'DuckDB extension that attaches a secrets service: one OIDC login, role-based access to secrets, delegation for servers.'},
    ],
    navbar: {
      title: 'tresor',
      logo: {
        alt: 'Hugr Lab',
        src: 'img/logo-circle.svg',
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
          href: 'https://hugr-lab.github.io/',
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
            {label: 'Main site', href: 'https://hugr-lab.github.io/'},
            {label: 'DuckDB MSSQL Extension', href: 'https://hugr-lab.github.io/mssql-extension/'},
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
