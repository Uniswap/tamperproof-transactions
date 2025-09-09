export default {
  transform: {
    '^.+\\.ts?$': ['ts-jest', { useESM: true, tsconfig: 'tsconfig.json' }],
  },
  extensionsToTreatAsEsm: ['.ts'],
  testEnvironment: 'node',
  testRegex: '/src/.*\\.(test|spec)?\\.(ts|tsx)$',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
};
