export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-enum': [
      2,
      'always',
      [
        'report',
        'protocol-ctf',
        'docs',
        'intent',
        'spec',
        'ci',
        'deps',
        'scripts',
      ],
    ],
  },
};
