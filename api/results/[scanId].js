// api/results/[scanId].js - Vercel Serverless Function
import fetch from 'node-fetch';

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

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

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!VIRUSTOTAL_API_KEY) {
    return res.status(500).json({ error: 'VirusTotal API key not configured' });
  }

  try {
    const { scanId } = req.query;

    if (!scanId) {
      return res.status(400).json({ error: 'Scan ID is required' });
    }

    // Get scan results from VirusTotal
    const response = await fetch(`https://www.virustotal.com/vtapi/v2/file/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${scanId}`);
    
    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.status}`);
    }

    const result = await response.json();

    // Check the response code
    if (result.response_code === 1) {
      // Scan completed
      res.status(200).json({
        status: 'completed',
        data: {
          positives: result.positives,
          total: result.total,
          md5: result.md5,
          sha1: result.sha1,
          sha256: result.sha256,
          scan_date: result.scan_date,
          permalink: result.permalink,
          scans: result.scans
        }
      });
    } else if (result.response_code === -2) {
      // Still processing
      res.status(200).json({
        status: 'processing',
        message: 'Scan is still in progress'
      });
    } else if (result.response_code === 0) {
      // File not found
      res.status(404).json({
        status: 'error',
        message: 'Scan ID not found'
      });
    } else {
      // Other error
      res.status(500).json({
        status: 'error',
        message: result.verbose_msg || 'Unknown error occurred'
      });
    }

  } catch (error) {
    console.error('Results API error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to get scan results',
      error: error.message
    });
  }
}
