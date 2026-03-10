const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const puppeteer = require('puppeteer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const USERS_FILE = path.join(__dirname, 'users.json');

// ─── 스캐너 정의 (새 스캐너 추가 시 여기에 추가) ───
const SCANNERS = [
  { id: 'vuln', name: '서버 취약점 점검', desc: 'Unix 서버 취약점 점검 (U-01~U-67 등)' },
  { id: 'pac4j', name: 'CVE-2026-29000 pac4j-jwt', desc: 'pac4j-jwt 인증 우회 취약점 점검' }
];

// Ensure upload directories exist
for (const s of SCANNERS) {
  const dir = path.join(UPLOADS_DIR, s.id);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// --- User management ---
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return []; }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

(function initAdmin() {
  const users = loadUsers();
  if (users.length === 0) {
    const hash = bcrypt.hashSync('admin', 10);
    saveUsers([{ username: 'admin', password: hash, role: 'admin', created: new Date().toISOString() }]);
    console.log('초기 admin 계정 생성됨 (ID: admin / PW: admin) - 반드시 비밀번호를 변경하세요!');
  }
})();

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files & body parser
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// Session
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 }
}));

// Auth middleware
function requireLogin(req, res, next) {
  if (req.session && req.session.user) return next();
  res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') return next();
  res.status(403).send('접근 권한이 없습니다.');
}

// Make user & scanners available in all templates
app.use((req, res, next) => {
  res.locals.currentUser = req.session ? req.session.user : null;
  res.locals.scanners = SCANNERS;
  res.locals.activeScanner = '';
  next();
});

// ─── Auth routes ───
app.get('/login', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  res.render('login', { error: req.query.error || null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.redirect('/login?error=' + encodeURIComponent('아이디 또는 비밀번호가 올바르지 않습니다.'));
  }
  req.session.user = { username: user.username, role: user.role };
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// ─── Admin routes ───
app.get('/admin', requireLogin, requireAdmin, (req, res) => {
  const users = loadUsers().map(u => ({ username: u.username, role: u.role, created: u.created }));
  res.render('admin', { users, message: req.query.message || null, error: req.query.error || null });
});

app.post('/admin/add-user', requireLogin, requireAdmin, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.redirect('/admin?error=' + encodeURIComponent('아이디와 비밀번호를 입력하세요.'));
  }
  if (username.length < 2 || password.length < 4) {
    return res.redirect('/admin?error=' + encodeURIComponent('아이디 2자 이상, 비밀번호 4자 이상 입력하세요.'));
  }
  const users = loadUsers();
  if (users.find(u => u.username === username)) {
    return res.redirect('/admin?error=' + encodeURIComponent('이미 존재하는 아이디입니다.'));
  }
  const hash = bcrypt.hashSync(password, 10);
  users.push({ username, password: hash, role: role === 'admin' ? 'admin' : 'user', created: new Date().toISOString() });
  saveUsers(users);
  res.redirect('/admin?message=' + encodeURIComponent(`사용자 "${username}" 추가 완료`));
});

app.post('/admin/delete-user', requireLogin, requireAdmin, (req, res) => {
  const { username } = req.body;
  if (username === 'admin') {
    return res.redirect('/admin?error=' + encodeURIComponent('기본 admin 계정은 삭제할 수 없습니다.'));
  }
  let users = loadUsers();
  users = users.filter(u => u.username !== username);
  saveUsers(users);
  res.redirect('/admin?message=' + encodeURIComponent(`사용자 "${username}" 삭제 완료`));
});

app.post('/admin/change-password', requireLogin, requireAdmin, (req, res) => {
  const { username, newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    return res.redirect('/admin?error=' + encodeURIComponent('비밀번호는 4자 이상 입력하세요.'));
  }
  const users = loadUsers();
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.redirect('/admin?error=' + encodeURIComponent('사용자를 찾을 수 없습니다.'));
  }
  user.password = bcrypt.hashSync(newPassword, 10);
  saveUsers(users);
  res.redirect('/admin?message=' + encodeURIComponent(`"${username}" 비밀번호 변경 완료`));
});

// Apply login requirement to all routes below
app.use(requireLogin);

// ─── 공통 유틸 ───
function isSafeFilename(filename) {
  return filename && !filename.includes('/') && !filename.includes('\\') && !filename.includes('..');
}

function getScannerDir(scannerId) {
  return path.join(UPLOADS_DIR, scannerId);
}

// ─── 스캐너별 JSON 파싱 ───
function parseVulnReport(filename, dir) {
  if (!isSafeFilename(filename)) return null;
  const filePath = path.join(dir, filename);
  try {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (!data.results || !Array.isArray(data.results)) return null;
    const stat = fs.statSync(filePath);
    return {
      filename, hostname: data.hostname || 'Unknown',
      os: data.os || '', os_version: data.os_version || '', kernel: data.kernel || '',
      ip_addresses: data.ip_addresses || [], scan_date: data.scan_date || '',
      summary: data.summary || { total: 0, pass: 0, fail: 0, na: 0 },
      upload_time: stat.mtime, results: data.results
    };
  } catch { return null; }
}

function parsePac4jReport(filename, dir) {
  if (!isSafeFilename(filename)) return null;
  const filePath = path.join(dir, filename);
  try {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (!data.results || !Array.isArray(data.results)) return null;
    const stat = fs.statSync(filePath);
    return {
      filename, hostname: data.hostname || 'Unknown',
      os: data.os || '', os_version: data.os_version || '', kernel: data.kernel || '',
      ip_addresses: data.ip_addresses || [], scan_date: data.scan_date || '',
      cve: data.cve || 'CVE-2026-29000', cvss: data.cvss || '10.0',
      host_environment: data.host_environment || '',
      container_runtime: data.container_runtime || '',
      summary: data.summary || { total: 0, vulnerable: 0, safe: 0, unknown: 0 },
      upload_time: stat.mtime, results: data.results
    };
  } catch { return null; }
}

function getAllReports(scannerId) {
  const dir = getScannerDir(scannerId);
  const parseFn = scannerId === 'pac4j' ? parsePac4jReport : parseVulnReport;
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
  const reports = [];
  for (const f of files) {
    const info = parseFn(f, dir);
    if (info) reports.push(info);
  }
  reports.sort((a, b) => b.upload_time - a.upload_time);
  return reports;
}

// ─── 스캐너별 통계 ───
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

function getSourceStats(results) {
  const stats = {};
  for (const r of results) {
    let src = r.source_type || '기타';
    // embedded_in_archive(...) -> 아카이브 내부
    if (src.startsWith('embedded_in_archive')) src = '아카이브 내부';
    else if (src === 'jar_file') src = 'JAR 파일';
    else if (src === 'pom.xml') src = 'Maven pom.xml';
    else if (src === 'build.gradle') src = 'Gradle';
    if (!stats[src]) stats[src] = { vulnerable: 0, safe: 0, unknown: 0 };
    if (r.status === '취약') stats[src].vulnerable++;
    else if (r.status === '양호') stats[src].safe++;
    else stats[src].unknown++;
  }
  return stats;
}

// ─── Multer 설정 (스캐너 ID별 분리) ───
function createUploader(scannerId) {
  const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, getScannerDir(scannerId)),
    filename: (req, file, cb) => {
      const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
      const ext = path.extname(originalName);
      const base = path.basename(originalName, ext);
      cb(null, `${base}_${Date.now()}${ext}`);
    }
  });
  return multer({
    storage,
    fileFilter: (req, file, cb) => {
      if (path.extname(file.originalname).toLowerCase() === '.json') cb(null, true);
      else cb(new Error('JSON 파일만 업로드 가능합니다.'));
    },
    limits: { fileSize: 50 * 1024 * 1024 }
  });
}

function handleUpload(scannerId) {
  const upload = createUploader(scannerId);
  return [
    (req, res, next) => {
      upload.array('files', 50)(req, res, (err) => {
        if (err) return res.redirect(`/${scannerId}?error=` + encodeURIComponent(err.message));
        next();
      });
    },
    (req, res) => {
      if (!req.files || req.files.length === 0) {
        return res.redirect(`/${scannerId}?error=` + encodeURIComponent('파일을 선택해주세요.'));
      }
      const dir = getScannerDir(scannerId);
      const validCount = [];
      const errors = [];

      for (const file of req.files) {
        const filePath = path.join(dir, file.filename);
        try {
          const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
          if (!data.results || !Array.isArray(data.results)) {
            fs.unlinkSync(filePath);
            errors.push(`${file.originalname}: results 배열이 없습니다.`);
            continue;
          }
          const hostname = (data.hostname || 'unknown').replace(/[^a-zA-Z0-9_\-]/g, '_');
          const scanDate = data.scan_date ? data.scan_date.substring(0, 10).replace(/-/g, '') : 'nodate';
          let newName = `${hostname}_${scanDate}.json`;
          let newPath = path.join(dir, newName);
          let counter = 1;
          while (fs.existsSync(newPath) && newPath !== filePath) {
            newName = `${hostname}_${scanDate}_${counter}.json`;
            newPath = path.join(dir, newName);
            counter++;
          }
          if (newPath !== filePath) fs.renameSync(filePath, newPath);
          validCount.push(newName);
        } catch {
          fs.unlinkSync(filePath);
          errors.push(`${file.originalname}: JSON 파싱 실패`);
        }
      }

      let msg = '';
      if (validCount.length > 0) msg += `${validCount.length}개 파일 업로드 완료.`;
      if (errors.length > 0) msg += ` 오류: ${errors.join(', ')}`;

      if (errors.length > 0 && validCount.length === 0) {
        return res.redirect(`/${scannerId}?error=` + encodeURIComponent(msg));
      }
      res.redirect(`/${scannerId}?message=` + encodeURIComponent(msg));
    }
  ];
}

// ─── 루트 → 기본 스캐너로 리다이렉트 ───
app.get('/', (req, res) => res.redirect('/vuln'));

// ═══════════════════════════════════════════
// 서버 취약점 점검 (vuln) 라우트
// ═══════════════════════════════════════════
app.get('/vuln', (req, res) => {
  const reports = getAllReports('vuln');
  res.render('index', {
    reports, activeScanner: 'vuln',
    message: req.query.message || null, error: req.query.error || null
  });
});

app.post('/vuln/upload', ...handleUpload('vuln'));

app.get('/vuln/report/:filename', (req, res) => {
  const report = parseVulnReport(req.params.filename, getScannerDir('vuln'));
  if (!report) return res.redirect('/vuln?error=' + encodeURIComponent('보고서를 찾을 수 없습니다.'));
  const categoryStats = getCategoryStats(report.results);
  res.render('report', { report, categoryStats, activeScanner: 'vuln' });
});

app.get('/vuln/download/:filename', async (req, res) => {
  const report = parseVulnReport(req.params.filename, getScannerDir('vuln'));
  if (!report) return res.status(404).send('보고서를 찾을 수 없습니다.');
  try {
    const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1400, height: 900 });
    // Set session cookie for puppeteer
    const cookies = [{ name: 'connect.sid', value: req.cookies?.['connect.sid'] || '', domain: 'localhost' }];
    await page.setCookie(...cookies).catch(() => {});
    const reportUrl = `http://localhost:${PORT}/vuln/report/${encodeURIComponent(req.params.filename)}`;
    await page.goto(reportUrl, { waitUntil: 'networkidle0', timeout: 30000 });
    const pdfData = await page.pdf({
      format: 'A4', printBackground: true, scale: 0.65,
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

app.post('/vuln/delete/:filename', (req, res) => {
  if (!isSafeFilename(req.params.filename)) return res.status(403).send('접근 거부');
  const filePath = path.join(getScannerDir('vuln'), req.params.filename);
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    res.redirect('/vuln?message=' + encodeURIComponent('파일이 삭제되었습니다.'));
  } catch {
    res.redirect('/vuln?error=' + encodeURIComponent('삭제 중 오류가 발생했습니다.'));
  }
});

// ═══════════════════════════════════════════
// CVE-2026-29000 pac4j-jwt (pac4j) 라우트
// ═══════════════════════════════════════════
app.get('/pac4j', (req, res) => {
  const reports = getAllReports('pac4j');
  res.render('pac4j-index', {
    reports, activeScanner: 'pac4j',
    message: req.query.message || null, error: req.query.error || null
  });
});

app.post('/pac4j/upload', ...handleUpload('pac4j'));

app.get('/pac4j/report/:filename', (req, res) => {
  const report = parsePac4jReport(req.params.filename, getScannerDir('pac4j'));
  if (!report) return res.redirect('/pac4j?error=' + encodeURIComponent('보고서를 찾을 수 없습니다.'));
  const sourceStats = getSourceStats(report.results);
  res.render('pac4j-report', { report, sourceStats, activeScanner: 'pac4j' });
});

app.get('/pac4j/download/:filename', async (req, res) => {
  const report = parsePac4jReport(req.params.filename, getScannerDir('pac4j'));
  if (!report) return res.status(404).send('보고서를 찾을 수 없습니다.');
  try {
    const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1400, height: 900 });
    const reportUrl = `http://localhost:${PORT}/pac4j/report/${encodeURIComponent(req.params.filename)}`;
    await page.goto(reportUrl, { waitUntil: 'networkidle0', timeout: 30000 });
    const pdfData = await page.pdf({
      format: 'A4', printBackground: true, scale: 0.65,
      margin: { top: '10mm', right: '10mm', bottom: '10mm', left: '10mm' }
    });
    await browser.close();
    const dateStr = report.scan_date ? report.scan_date.substring(0, 10) : 'nodate';
    const downloadName = encodeURIComponent(`CVE-2026-29000_${report.hostname}_${dateStr}.pdf`);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${downloadName}`);
    res.send(Buffer.from(pdfData));
  } catch (err) {
    console.error('PDF generation error:', err);
    res.status(500).send('PDF 생성 중 오류가 발생했습니다.');
  }
});

app.post('/pac4j/delete/:filename', (req, res) => {
  if (!isSafeFilename(req.params.filename)) return res.status(403).send('접근 거부');
  const filePath = path.join(getScannerDir('pac4j'), req.params.filename);
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    res.redirect('/pac4j?message=' + encodeURIComponent('파일이 삭제되었습니다.'));
  } catch {
    res.redirect('/pac4j?error=' + encodeURIComponent('삭제 중 오류가 발생했습니다.'));
  }
});

app.listen(PORT, () => {
  console.log(`취약점 점검 보고서 시스템 실행 중: http://localhost:${PORT}`);
});
