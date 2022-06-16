module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*"
    },
    develop: {
      host: "127.0.0.1",
      port: 9545,
      network_id: "*"
    },
    ganache: {
      host: "127.0.0.1",
      port: 7545,
      network_id: "*"
    },
    dashboard: {
    }
  },
  compilers: {
    solc: {
      version: "pragma"
    }
  },
  db: {
    enabled: false,
    host: "127.0.0.1",
  }
};
