// Our own security plugins, at strict, on everything that is meant to be safe.
// The labs' vulnerable servers and exploits are linted by scripts/lab-lint.mjs instead,
// where a hit is an expected answer rather than a failure.
import nodeSecurity from 'eslint-plugin-node-security';
import secureCoding from 'eslint-plugin-secure-coding';
import mcpSdkSecurity from 'eslint-plugin-mcp-sdk-security';

const flat = (c) => (Array.isArray(c) ? c : [c]);

export default [
  {
    ignores: [
      '**/node_modules/**',
      'protocol-ctf/challenges/**',
      'protocol-ctf/solutions/**',
    ],
  },
  {
    files: ['**/*.mjs', '**/*.js'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
  },
  ...flat(nodeSecurity.configs.strict),
  ...flat(secureCoding.configs.strict),
  ...flat(mcpSdkSecurity.configs.strict),
];
