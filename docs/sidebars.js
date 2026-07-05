// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    'intro',
    'architecture',
    'getting-started',
    {
      type: 'category',
      label: 'Guides',
      collapsed: false,
      items: [
        'guides/issuance',
        'guides/presentation',
        'guides/dc-api',
        'guides/proximity',
        'guides/trust-and-audit',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      items: ['reference/facade', 'reference/ports'],
    },
    'android-demo',
  ],
};

export default sidebars;
