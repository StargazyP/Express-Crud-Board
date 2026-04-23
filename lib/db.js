const MongoClient = require("mongodb").MongoClient;

function connectMongo(dbUrl, dbName = "server") {
  return new Promise((resolve, reject) => {
    MongoClient.connect(dbUrl, { useUnifiedTopology: true }, (err, client) => {
      if (err) return reject(err);
      resolve(client.db(dbName));
    });
  });
}

module.exports = {
  connectMongo,
};
