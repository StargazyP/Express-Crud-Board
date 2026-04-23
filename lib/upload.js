const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs/promises");

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, "./public/image"),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const safeExt = [".png", ".jpg", ".jpeg", ".gif", ".webp"].includes(ext)
      ? ext
      : "";
    const name = crypto.randomBytes(16).toString("hex") + safeExt;
    cb(null, name);
  },
});

const upload = multer({
  storage,
  limits: {
    files: 10,
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (_req, file, cb) => {
    const ok =
      typeof file.mimetype === "string" && file.mimetype.startsWith("image/");
    cb(ok ? null : new Error("Only image uploads are allowed"), ok);
  },
});

async function validateUploadedImages(files) {
  const { fileTypeFromFile } = await import("file-type");
  const safe = [];

  for (const f of files) {
    const detected = await fileTypeFromFile(f.path);
    const ok =
      detected &&
      typeof detected.mime === "string" &&
      detected.mime.startsWith("image/");
    if (!ok) {
      await fs.unlink(f.path).catch(() => {});
      throw new Error("Invalid upload");
    }
    safe.push(f);
  }
  return safe;
}

module.exports = {
  upload,
  validateUploadedImages,
};
