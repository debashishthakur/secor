const { sequelize } = require("./db");

async function findOrdersByStatus(status) {
  let sql = "SELECT * FROM orders";
  sql += " WHERE status = '" + status + "'";
  return sequelize.query(sql);
}

module.exports = { findOrdersByStatus };
