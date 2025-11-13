import crypto from "crypto";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  const { pdf_data } = req.body;

  if (!pdf_data) {
    return res.status(400).json({ error: "Missing pdf_data" });
  }

  try {
    // Hitung hash PDF
    const hash = crypto.createHash("sha256").update(pdf_data).digest("base64");
    // Simulasi tanda tangan digital
    const signature = crypto.createHash("sha256").update(hash + "secret_key").digest("base64");

    res.status(200).json({
      hash_b64: hash,
      signature_b64: signature
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
