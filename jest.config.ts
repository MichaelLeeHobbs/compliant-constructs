import type { Config } from 'jest'

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.spec.ts', '**/*.test.ts'],
  testPathIgnorePatterns: ['/node_modules/'],
  collectCoverageFrom: ['src/**/*.ts', '!src/**/*.d.ts'],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        tsconfig: {
          module: 'commonjs',
          moduleResolution: 'node',
          esModuleInterop: true,
          allowSyntheticDefaultImports: true,
          isolatedModules: true,
          // TypeScript 6 deprecated `moduleResolution: 'node'` (removed in 7).
          // Keep using it under ts-jest until the test transform migrates to
          // 'node16'/'nodenext'; suppress the deprecation in the meantime.
          ignoreDeprecations: '6.0',
        },
      },
    ],
  },
  moduleNameMapper: {
    // Source uses NodeNext, so relative imports carry an explicit `.js`
    // extension that does not exist on disk pre-build. Strip it for ts-jest,
    // which resolves with classic node resolution.
    '^(\\.{1,2}/.*)\\.js$': '$1',
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  verbose: true,
  workerIdleMemoryLimit: '512MB',
}

export default config
