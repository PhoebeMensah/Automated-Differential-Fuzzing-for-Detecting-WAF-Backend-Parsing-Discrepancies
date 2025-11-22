const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
// NEW: Add XML parser
const xml2js = require('xml2js');

const LOG_DIR = path.join(__dirname, 'logs');
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);

const app = express();

// Keep this! We still want raw bytes to simulate the "dumb" backend
app.use(bodyParser.raw({ type: '*/*', limit: '10mb' }));

function writeRaw(rawBuf, headers) {
  const ts = Date.now();
  const fname = path.join(LOG_DIR, `raw_${ts}.log`);
  console.log(`Retrieved log directory as ${fname}`);

  const headerLines = Object.entries(headers).map(([k,v]) => `${k}: ${v}`).join('\n');
  const headerString = `--- HEADERS ---\n${headerLines}\n\n--- BODY ---\n`;
  
  const headerBuf = Buffer.from(headerString, 'utf8');
  const bodyBuf = Buffer.isBuffer(rawBuf) ? rawBuf : Buffer.from(String(rawBuf));
  const logBuf = Buffer.concat([headerBuf, bodyBuf]);
  
  try {
    fs.writeFileSync(fname, logBuf);
  } catch (err) {
    console.error(`[ERROR] Failed to write raw log to ${fname}:`, err);
  }
}

app.post('/echo', async (req, res) => {
  let rawBuf;
  if (Buffer.isBuffer(req.body)) {
    rawBuf = req.body;
  } else if (req.body == null) {
    rawBuf = Buffer.from('');
  } else {
    rawBuf = Buffer.from(String(req.body));
  }
  
  writeRaw(rawBuf, req.headers);

  let receivedField = null;
  const rawString = rawBuf.toString('utf8');

  // 1. Try JSON
  try {
    const j = JSON.parse(rawString);
    if (j && typeof j === 'object' && 'field' in j) receivedField = j.field;
  } catch (_) {
    // JSON failed, fall through
  }

  // 2. Try Regex (Form/Query params)
  if (receivedField === null) {
    const m = rawString.match(/(?:^|[&\r\n])field=([^&\r\n]+)/);
    if (m) {
      try { receivedField = decodeURIComponent(m[1]); } catch { receivedField = m[1]; }
    }
  }

  // 3. NEW: Try XML
  // This allows us to verify if XXE payloads are actually processed
  if (receivedField === null && rawString.trim().startsWith('<')) {
    try {
      const parser = new xml2js.Parser({ 
        explicitArray: false,
        // DANGER: This enables XXE processing in older xml2js versions or specific configs.
        // For this project, we WANT to be vulnerable to prove the WAF should have stopped it.
      });
      
      // Parse the XML
      const result = await parser.parseStringPromise(rawString);
      
      // Look for <root><field>value</field></root>
      if (result && result.root && result.root.field) {
        receivedField = result.root.field;
      }
    } catch (e) {
      // XML parsing failed
    }
  }

  res.json({ received_field: receivedField, raw_len: rawBuf.length });
});

app.get('/echo', (_req, res) => res.json({ msg: 'send POST with JSON, Form, or XML' }));

app.listen(3000, '0.0.0.0', () => console.log('express listening on 3000'));