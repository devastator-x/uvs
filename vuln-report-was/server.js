const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const puppeteer = require('puppeteer');

const app = express();
const PORT = 3000;
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Ensure uploads directory exists
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    // Read JSON to extract hostname and date for naming
    const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
    const ext = path.extname(originalName);
    const base = path.basename(originalName, ext);
    const timestamp = Date.now();
    cb(null, `${base}_${timestamp}${ext}`);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() === '.json') {
      cb(null, true);
    } else {
      cb(new Error('JSON 파일만 업로드 가능합니다.'));
    }
  },
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB
});

// Helper: validate filename (prevent path traversal)
function isSafeFilename(filename) {
  return filename && !filename.includes('/') && !filename.includes('\\') && !filename.includes('..');
}

// Helper: parse JSON file and extract summary info
function parseReportFile(filename) {
  if (!isSafeFilename(filename)) return null;
  const filePath = path.join(UPLOADS_DIR, filename);
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);
    if (!data.results || !Array.isArray(data.results)) {
      return null;
    }
    const stat = fs.statSync(filePath);
    return {
      filename,
      hostname: data.hostname || 'Unknown',
      os: data.os || '',
      os_version: data.os_version || '',
      kernel: data.kernel || '',
      ip_addresses: data.ip_addresses || [],
      scan_date: data.scan_date || '',
      summary: data.summary || { total: 0, pass: 0, fail: 0, na: 0 },
      upload_time: stat.mtime,
      results: data.results
    };
  } catch (e) {
    return null;
  }
}

// Helper: get all reports
function getAllReports() {
  const files = fs.readdirSync(UPLOADS_DIR).filter(f => f.endsWith('.json'));
  const reports = [];
  for (const f of files) {
    const info = parseReportFile(f);
    if (info) reports.push(info);
  }
  reports.sort((a, b) => b.upload_time - a.upload_time);
  return reports;
}

// Helper: get category stats from results
function getCategoryStats(results) {
  const cats = {};
  for (const r of results) {
    const cat = r.category || '기타';
    if (!cats[cat]) cats[cat] = { pass: 0, fail: 0, na: 0 };
    if (r.status === '양호') cats[cat].pass++;
    else if (r.status === '취약') cats[cat].fail++;
    else cats[cat].na++;
  }
  return cats;
}

// GET / - Main page
app.get('/', (req, res) => {
  const reports = getAllReports();
  res.render('index', { reports, message: req.query.message || null, error: req.query.error || null });
});

// POST /upload - Upload JSON files
app.post('/upload', (req, res, next) => {
  upload.array('files', 50)(req, res, (err) => {
    if (err) {
      return res.redirect('/?error=' + encodeURIComponent(err.message));
    }
    next();
  });
}, (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.redirect('/?error=' + encodeURIComponent('파일을 선택해주세요.'));
  }

  // Validate and rename files
  const validCount = [];
  const errors = [];

  for (const file of req.files) {
    const filePath = path.join(UPLOADS_DIR, file.filename);
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(raw);
      if (!data.results || !Array.isArray(data.results)) {
        fs.unlinkSync(filePath);
        errors.push(`${file.originalname}: results 배열이 없습니다.`);
        continue;
      }
      // Rename to hostname_date format
      const hostname = (data.hostname || 'unknown').replace(/[^a-zA-Z0-9_\-]/g, '_');
      const scanDate = data.scan_date ? data.scan_date.substring(0, 10).replace(/-/g, '') : 'nodate';
      let newName = `${hostname}_${scanDate}.json`;
      let newPath = path.join(UPLOADS_DIR, newName);
      let counter = 1;
      while (fs.existsSync(newPath) && newPath !== filePath) {
        newName = `${hostname}_${scanDate}_${counter}.json`;
        newPath = path.join(UPLOADS_DIR, newName);
        counter++;
      }
      if (newPath !== filePath) {
        fs.renameSync(filePath, newPath);
      }
      validCount.push(newName);
    } catch (e) {
      fs.unlinkSync(filePath);
      errors.push(`${file.originalname}: JSON 파싱 실패`);
    }
  }

  let msg = '';
  if (validCount.length > 0) msg += `${validCount.length}개 파일 업로드 완료.`;
  if (errors.length > 0) msg += ` 오류: ${errors.join(', ')}`;

  if (errors.length > 0 && validCount.length === 0) {
    return res.redirect('/?error=' + encodeURIComponent(msg));
  }
  res.redirect('/?message=' + encodeURIComponent(msg));
});

// GET /report/:filename - Report page
app.get('/report/:filename', (req, res) => {
  const report = parseReportFile(req.params.filename);
  if (!report) {
    return res.redirect('/?error=' + encodeURIComponent('보고서를 찾을 수 없습니다.'));
  }
  const categoryStats = getCategoryStats(report.results);
  res.render('report', { report, categoryStats });
});

// GET /download/:filename - Download PDF (puppeteer navigates to the report page itself)
app.get('/download/:filename', async (req, res) => {
  const report = parseReportFile(req.params.filename);
  if (!report) {
    return res.status(404).send('보고서를 찾을 수 없습니다.');
  }

  try {
    const browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    const page = await browser.newPage();
    await page.setViewport({ width: 1400, height: 900 });
    const reportUrl = `http://localhost:${PORT}/report/${encodeURIComponent(req.params.filename)}`;
    await page.goto(reportUrl, { waitUntil: 'networkidle0', timeout: 30000 });

    const pdfData = await page.pdf({
      format: 'A4',
      landscape: false,
      printBackground: true,
      scale: 0.65,
      margin: { top: '10mm', right: '10mm', bottom: '10mm', left: '10mm' }
    });
    await browser.close();

    const dateStr = report.scan_date ? report.scan_date.substring(0, 10) : 'nodate';
    const downloadName = encodeURIComponent(`취약점점검보고서_${report.hostname}_${dateStr}.pdf`);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${downloadName}`);
    res.send(Buffer.from(pdfData));
  } catch (err) {
    console.error('PDF generation error:', err);
    res.status(500).send('PDF 생성 중 오류가 발생했습니다.');
  }
});

// POST /delete/:filename - Delete uploaded file
app.post('/delete/:filename', (req, res) => {
  if (!isSafeFilename(req.params.filename)) {
    return res.status(403).send('접근 거부');
  }
  const filePath = path.join(UPLOADS_DIR, req.params.filename);
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    res.redirect('/?message=' + encodeURIComponent('파일이 삭제되었습니다.'));
  } catch (e) {
    res.redirect('/?error=' + encodeURIComponent('삭제 중 오류가 발생했습니다.'));
  }
});

app.listen(PORT, () => {
  console.log(`취약점 점검 보고서 시스템 실행 중: http://localhost:${PORT}`);
});
