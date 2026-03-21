// CJS stub used by Jest to replace the ESM @kubernetes/client-node package.
// KubeConfig, BatchV1Api, and V1Job are the only symbols K8sSandbox.ts needs.
class KubeConfig {
  loadFromDefault() {}
  makeApiClient() {
    return {
      createNamespacedJob: jest.fn().mockResolvedValue({}),
      deleteNamespacedJob: jest.fn().mockResolvedValue({}),
      readNamespacedJob: jest.fn().mockResolvedValue({}),
      listNamespacedJob: jest.fn().mockResolvedValue({ items: [] }),
    };
  }
}

// Empty class exported to satisfy the module interface; K8sSandbox uses it
// only as a type token passed to makeApiClient().
class BatchV1Api {}

module.exports = { KubeConfig, BatchV1Api };
