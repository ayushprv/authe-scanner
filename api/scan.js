// api/scan.js - Vercel Serverless Function
import formidable from 'formidable';
import fetch from 'node-fetch';
import fs from 'fs';

// This is safe because it's running on the server side
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

export const config = {
  api: {
    bodyParser: false,
  },
};

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!VIRUSTOTAL_API_KEY) {
    return res.status(500).json({ error: 'VirusTotal API key not configured' });
  }

  try {
    // Parse the uploaded file
    const form = formidable({
      maxFileSize: 50 * 1024 * 1024, // 50MB limit
      keepExtensions: true,
    });

    const [fields, files] = await form.parse(req);
    const uploadedFile = files.file?.[0];

    if (!uploadedFile) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Check if it's an APK file
    if (!uploadedFile.originalFilename?.endsWith('.apk')) {
      return res.status(400).json({ error: 'Only APK files are allowed' });
    }

    // Upload to VirusTotal
    const formData = new FormData();
    const fileBuffer = fs.readFileSync(uploadedFile.filepath);
    const blob = new Blob([fileBuffer], { type: 'application/vnd.android.package-archive' });
    
    formData.append('file', blob, uploadedFile.originalFilename);

    const uploadResponse = await fetch('https://www.virustotal.com/vtapi/v2/file/scan', {
      method: 'POST',
      headers: {
        'apikey': VIRUSTOTAL_API_KEY,
      },
      body: formData,
    });

    if (!uploadResponse.ok) {
      throw new Error(`VirusTotal upload failed: ${uploadResponse.status}`);
    }

    const uploadResult = await uploadResponse.json();

    // Clean up the uploaded file
    fs.unlinkSync(uploadedFile.filepath);

    // Return the scan ID
    res.status(200).json({
      success: true,
      scanId: uploadResult.resource,
      message: 'File uploaded successfully, analysis started'
    });

  } catch (error) {
    console.error('Scan API error:', error);
    res.status(500).json({
      error: 'Failed to process file',
      message: error.message
    });
  }
}
