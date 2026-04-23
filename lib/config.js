const BASE_PATH = (process.env.BASE_PATH || "").replace(/\/$/, "");

function absUrl(p) {
  const normalized = p.startsWith("/") ? p : `/${p}`;
  return BASE_PATH + normalized;
}

module.exports = {
  BASE_PATH,
  absUrl,
};
