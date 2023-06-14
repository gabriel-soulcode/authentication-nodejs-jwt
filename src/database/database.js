const Sequelize = require("sequelize");

const connection = new Sequelize({
  dialect: "sqlite",
  storage: "database.db",
});

module.exports = connection;
