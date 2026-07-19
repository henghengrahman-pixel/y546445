'use strict';
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const methodOverride = require('method-override');
const multer = require('multer');
const cron = require('node-cron');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('trust proxy', 1);
function env(name, fallback=''){ const v=process.env[name]; return v==null?fallback:String(v).trim().replace(/^['\"]|['\"]$/g,''); }
const PORT = Number(process.env.PORT || 3000);
const APP_NAME = env('APP_NAME','G - 8008 RP');
const DATA_DIR = env('DATA_DIR',path.join(__dirname, '..', 'data'));
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'g8008rp.sqlite');
const IDLE_MS = Number(process.env.IDLE_TIMEOUT_MINUTES || 60) * 60 * 1000;
const ABSOLUTE_MS = Number(process.env.ABSOLUTE_SESSION_HOURS || 12) * 60 * 60 * 1000;
const TZ = env('TIMEZONE','Asia/Jakarta');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      login_id TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'admin',
      totp_secret TEXT,
      totp_enabled INTEGER NOT NULL DEFAULT 0,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS offices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      address TEXT, country TEXT, city TEXT, manager TEXT,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS groups_tbl (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      office_id INTEGER REFERENCES offices(id) ON DELETE SET NULL,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS staff (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      staff_code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      phone TEXT, telegram TEXT,
      office_id INTEGER REFERENCES offices(id) ON DELETE SET NULL,
      group_id INTEGER REFERENCES groups_tbl(id) ON DELETE SET NULL,
      shift TEXT, duty TEXT, position TEXT,
      start_date TEXT,
      employment_status TEXT NOT NULL DEFAULT 'ACTIVE',
      notes TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      staff_id INTEGER NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
      doc_type TEXT NOT NULL CHECK(doc_type IN ('PASSPORT','VISA','WP','CONTRACT')),
      doc_number TEXT,
      issued_date TEXT,
      expiry_date TEXT NOT NULL,
      file_path TEXT,
      notes TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS leave_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      staff_id INTEGER NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      leave_type TEXT NOT NULL DEFAULT 'CUTI',
      replacement_staff TEXT,
      reason TEXT,
      status TEXT NOT NULL DEFAULT 'PENDING',
      approved_by TEXT,
      approved_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS warnings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      staff_id INTEGER NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
      level TEXT NOT NULL,
      warning_date TEXT NOT NULL,
      reason TEXT NOT NULL,
      details TEXT,
      valid_until TEXT,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      created_by TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS former_employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      staff_id INTEGER UNIQUE NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
      last_work_date TEXT NOT NULL,
      exit_type TEXT NOT NULL,
      exit_reason TEXT NOT NULL,
      rehire_eligible INTEGER NOT NULL DEFAULT 1,
      notes TEXT,
      created_by TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS blacklists (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      staff_id INTEGER UNIQUE NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
      level TEXT NOT NULL,
      reason TEXT NOT NULL,
      permanent INTEGER NOT NULL DEFAULT 1,
      review_date TEXT,
      created_by TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'INFO',
      entity_type TEXT,
      entity_id INTEGER,
      dedupe_key TEXT UNIQUE,
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id INTEGER,
      details TEXT,
      ip TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);
  const cols=db.prepare("PRAGMA table_info(users)").all().map(x=>x.name);
  if(!cols.includes('must_change_password')) db.exec("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0");
  if(!cols.includes('updated_at')) db.exec("ALTER TABLE users ADD COLUMN updated_at TEXT");
  const dcols=db.prepare("PRAGMA table_info(documents)").all().map(x=>x.name);
  if(!dcols.includes('process_status')) db.exec("ALTER TABLE documents ADD COLUMN process_status TEXT NOT NULL DEFAULT 'ACTIVE'");
  if(!dcols.includes('process_note')) db.exec("ALTER TABLE documents ADD COLUMN process_note TEXT");
  if(!dcols.includes('agent_name')) db.exec("ALTER TABLE documents ADD COLUMN agent_name TEXT");
  if(!dcols.includes('updated_at')) db.exec("ALTER TABLE documents ADD COLUMN updated_at TEXT");
}

function seed() {
  const loginId = env('ADMIN_ID','ADM-0001');
  const password = env('ADMIN_PASSWORD','Admin123!');
  const name = env('ADMIN_NAME','Super Admin');
  const exists = db.prepare('SELECT id FROM users WHERE login_id=?').get(loginId);
  if (!exists) {
    db.prepare('INSERT INTO users(login_id,name,password_hash,role,active) VALUES(?,?,?,?,1)').run(loginId, name, bcrypt.hashSync(password, 12), 'owner');
    console.log(`[Auth] Super Admin dibuat: ${loginId}`);
  } else if (env('SYNC_ADMIN_ON_BOOT','true').toLowerCase() !== 'false') {
    db.prepare("UPDATE users SET name=?,password_hash=?,role='owner',active=1,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(name,bcrypt.hashSync(password,12),exists.id);
    console.log(`[Auth] Super Admin disinkronkan dari ENV: ${loginId}`);
  }
  if (!db.prepare('SELECT id FROM offices LIMIT 1').get()) {
    const oid = db.prepare('INSERT INTO offices(name,country,city,manager) VALUES(?,?,?,?)').run('Kantor Utama','Cambodia','Poipet','Owner').lastInsertRowid;
    for (const g of ['OMTOGEL','RUPIAHTOTO','DENTOTO']) db.prepare('INSERT INTO groups_tbl(office_id,name,description) VALUES(?,?,?)').run(oid,g,'Group operasional');
  }
}

migrate(); seed();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use('/public', express.static(path.join(__dirname, '..', 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(session({
  secret: env('SESSION_SECRET','change-this-session-secret-minimum-32-chars'),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'lax', secure: env('NODE_ENV') === 'production', maxAge: IDLE_MS }
}));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req,_file,cb)=>cb(null,UPLOAD_DIR),
    filename: (_req,file,cb)=>cb(null,`${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(file.originalname).toLowerCase()}`)
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req,file,cb)=> cb(null, ['application/pdf','image/jpeg','image/png','image/webp'].includes(file.mimetype))
});

function daysUntil(dateStr) { return Math.ceil((new Date(`${dateStr}T23:59:59`).getTime() - Date.now()) / 86400000); }
function fmtDate(d) { if (!d) return '-'; return new Intl.DateTimeFormat('id-ID',{dateStyle:'medium', timeZone:TZ}).format(new Date(`${d}T00:00:00`)); }
function audit(req, action, entityType='', entityId=null, details='') {
  db.prepare('INSERT INTO audit_logs(user_id,action,entity_type,entity_id,details,ip) VALUES(?,?,?,?,?,?)').run(req.session.user?.id || null,action,entityType,entityId,details,req.ip);
}
function flash(req,type,message){ req.session.flash={type,message}; }
function auth(req,res,next){
  if(!req.session.user) return res.redirect('/login');
  const now=Date.now();
  if ((req.session.lastActivity && now-req.session.lastActivity>IDLE_MS) || (req.session.loginAt && now-req.session.loginAt>ABSOLUTE_MS)) {
    return req.session.destroy(()=>res.redirect('/login?expired=1'));
  }
  req.session.lastActivity=now; next();
}
function role(...roles){ return (req,res,next)=> roles.includes(req.session.user.role) ? next() : res.status(403).render('error',{message:'Akses ditolak'}); }

app.use((req,res,next)=>{
  res.locals.appName=APP_NAME; res.locals.user=req.session.user || null; res.locals.flash=req.session.flash || null; delete req.session.flash;
  res.locals.fmtDate=fmtDate; res.locals.daysUntil=daysUntil;
  res.locals.notificationCount=req.session.user ? db.prepare('SELECT COUNT(*) c FROM notifications WHERE is_read=0').get().c : 0;
  next();
});

app.get('/health', (_req,res)=>res.json({status:'ok',service:'g-8008-rp',time:new Date().toISOString()}));
app.get('/', (req,res)=>res.redirect(req.session.user?'/dashboard':'/login'));
app.get('/login',(req,res)=>res.render('login',{error:null,expired:req.query.expired}));
app.post('/login',(req,res)=>{
  const u=db.prepare('SELECT * FROM users WHERE login_id=? AND active=1').get((req.body.login_id||'').trim());
  if(!u || !bcrypt.compareSync(req.body.password||'',u.password_hash)) return res.status(401).render('login',{error:'ID atau password salah.',expired:false});
  req.session.pendingUser={id:u.id,login_id:u.login_id,name:u.name,role:u.role};
  if(!u.totp_enabled){
    const secret=authenticator.generateSecret(); db.prepare('UPDATE users SET totp_secret=? WHERE id=?').run(secret,u.id); req.session.setupSecret=secret; return res.redirect('/2fa/setup');
  }
  res.redirect('/2fa/verify');
});
app.get('/2fa/setup', async(req,res)=>{
  if(!req.session.pendingUser || !req.session.setupSecret) return res.redirect('/login');
  const uri=authenticator.keyuri(req.session.pendingUser.login_id,APP_NAME,req.session.setupSecret);
  res.render('twofa-setup',{qr:await QRCode.toDataURL(uri),secret:req.session.setupSecret,error:null});
});
app.post('/2fa/setup',(req,res)=>{
  if(!req.session.pendingUser || !req.session.setupSecret) return res.redirect('/login');
  if(!authenticator.check(req.body.token||'',req.session.setupSecret)) return QRCode.toDataURL(authenticator.keyuri(req.session.pendingUser.login_id,APP_NAME,req.session.setupSecret)).then(qr=>res.status(400).render('twofa-setup',{qr,secret:req.session.setupSecret,error:'Kode tidak valid.'}));
  db.prepare('UPDATE users SET totp_enabled=1 WHERE id=?').run(req.session.pendingUser.id); finishLogin(req,res);
});
app.get('/2fa/verify',(req,res)=> req.session.pendingUser ? res.render('twofa-verify',{error:null}) : res.redirect('/login'));
app.post('/2fa/verify',(req,res)=>{
  if(!req.session.pendingUser) return res.redirect('/login');
  const u=db.prepare('SELECT totp_secret FROM users WHERE id=?').get(req.session.pendingUser.id);
  if(!u || !authenticator.check(req.body.token||'',u.totp_secret)) return res.status(401).render('twofa-verify',{error:'Kode Google Authenticator salah.'});
  finishLogin(req,res);
});
function finishLogin(req,res){ req.session.user=req.session.pendingUser; delete req.session.pendingUser; delete req.session.setupSecret; req.session.loginAt=Date.now(); req.session.lastActivity=Date.now(); audit(req,'LOGIN'); res.redirect('/dashboard'); }
app.post('/logout',auth,(req,res)=>{audit(req,'LOGOUT');req.session.destroy(()=>res.redirect('/login'));});

app.get('/dashboard',auth,(req,res)=>{
  generateExpiryNotifications();
  const stats={
    staff:db.prepare("SELECT COUNT(*) c FROM staff WHERE employment_status='ACTIVE'").get().c,
    offices:db.prepare('SELECT COUNT(*) c FROM offices WHERE active=1').get().c,
    groups:db.prepare('SELECT COUNT(*) c FROM groups_tbl WHERE active=1').get().c,
    former:db.prepare("SELECT COUNT(*) c FROM staff WHERE employment_status='FORMER'").get().c,
    blacklist:db.prepare('SELECT COUNT(*) c FROM blacklists').get().c,
    sp:db.prepare("SELECT COUNT(*) c FROM warnings WHERE status='ACTIVE'").get().c,
    leave:db.prepare("SELECT COUNT(*) c FROM leave_requests WHERE status='APPROVED' AND end_date>=date('now')").get().c
  };
  const docStats={};
  for (const t of ['PASSPORT','VISA','WP','CONTRACT']) {
    const limit=threshold(t);
    docStats[t]=db.prepare(`SELECT COUNT(*) c FROM documents d JOIN staff s ON s.id=d.staff_id WHERE s.employment_status='ACTIVE' AND julianday(d.expiry_date)-julianday('now')<=?`).get(limit).c;
  }
  const expiring=db.prepare(`SELECT d.*,s.name,s.staff_code,o.name office_name,g.name group_name FROM documents d JOIN staff s ON s.id=d.staff_id LEFT JOIN offices o ON o.id=s.office_id LEFT JOIN groups_tbl g ON g.id=s.group_id WHERE s.employment_status='ACTIVE' ORDER BY date(d.expiry_date) LIMIT 12`).all();
  const groupStats=db.prepare(`SELECT g.id,g.name,COUNT(s.id) staff_count FROM groups_tbl g LEFT JOIN staff s ON s.group_id=g.id AND s.employment_status='ACTIVE' WHERE g.active=1 GROUP BY g.id,g.name ORDER BY g.name`).all();
  const upcomingLeave=db.prepare(`SELECT l.*,s.name,s.staff_code,o.name office_name,g.name group_name FROM leave_requests l JOIN staff s ON s.id=l.staff_id LEFT JOIN offices o ON o.id=s.office_id LEFT JOIN groups_tbl g ON g.id=s.group_id WHERE l.status='APPROVED' AND date(l.end_date)>=date('now') ORDER BY date(l.start_date) LIMIT 10`).all();
  const notifications=db.prepare('SELECT * FROM notifications ORDER BY is_read ASC,id DESC LIMIT 10').all();
  res.render('dashboard',{stats,docStats,groupStats,expiring,upcomingLeave,notifications});
});


// Dokumen terpisah: Paspor, Visa, Work Permit, Kontrak
app.get('/documents/:type',auth,(req,res)=>{
  const map={passport:'PASSPORT',visa:'VISA',wp:'WP',contract:'CONTRACT'};
  const type=map[String(req.params.type).toLowerCase()];
  if(!type) return res.status(404).render('error',{message:'Jenis dokumen tidak ditemukan'});
  const q=(req.query.q||'').trim(), group=req.query.group||'';
  let sql=`SELECT d.*,s.name,s.staff_code,s.shift,s.duty,o.name office_name,g.name group_name FROM documents d JOIN staff s ON s.id=d.staff_id LEFT JOIN offices o ON o.id=s.office_id LEFT JOIN groups_tbl g ON g.id=s.group_id WHERE d.doc_type=?`;
  const p=[type];
  if(q){sql+=' AND (s.name LIKE ? OR s.staff_code LIKE ? OR d.doc_number LIKE ?)';p.push(`%${q}%`,`%${q}%`,`%${q}%`);}
  if(group){sql+=' AND s.group_id=?';p.push(group);}
  sql+=' ORDER BY date(d.expiry_date),s.name';
  res.render('documents-list',{type,items:db.prepare(sql).all(...p),groups:db.prepare('SELECT * FROM groups_tbl WHERE active=1 ORDER BY name').all(),offices:db.prepare('SELECT * FROM offices WHERE active=1 ORDER BY name').all(),staff:db.prepare("SELECT s.id,s.name,s.staff_code,g.name group_name,o.name office_name FROM staff s LEFT JOIN groups_tbl g ON g.id=s.group_id LEFT JOIN offices o ON o.id=s.office_id WHERE s.employment_status='ACTIVE' ORDER BY s.name").all(),q,group,limit:threshold(type)});
});

// Daftar staf per group
app.get('/groups/:id/staff',auth,(req,res)=>{
  const group=db.prepare('SELECT g.*,o.name office_name FROM groups_tbl g LEFT JOIN offices o ON o.id=g.office_id WHERE g.id=?').get(req.params.id);
  if(!group) return res.status(404).render('error',{message:'Group tidak ditemukan'});
  const items=db.prepare(`SELECT s.*,o.name office_name,(SELECT COUNT(*) FROM warnings w WHERE w.staff_id=s.id) warning_count,(SELECT level FROM blacklists b WHERE b.staff_id=s.id) blacklist_level FROM staff s LEFT JOIN offices o ON o.id=s.office_id WHERE s.group_id=? ORDER BY CASE s.employment_status WHEN 'ACTIVE' THEN 0 ELSE 1 END,s.name`).all(group.id);
  res.render('group-staff',{group,items});
});

// Multi Admin - hanya Super Admin/owner
app.get('/admins',auth,role('owner'),(req,res)=>{
  res.render('admins',{items:db.prepare("SELECT id,login_id,name,role,totp_enabled,active,created_at,updated_at FROM users ORDER BY CASE role WHEN 'owner' THEN 0 ELSE 1 END,name").all()});
});
app.post('/admins',auth,role('owner'),(req,res)=>{
  const loginId=(req.body.login_id||'').trim(); const password=req.body.password||''; const name=(req.body.name||'').trim(); const roleName=req.body.role||'admin';
  if(!loginId||!name||password.length<8){flash(req,'error','ID, nama, dan password minimal 8 karakter wajib diisi.');return res.redirect('/admins');}
  try{const r=db.prepare('INSERT INTO users(login_id,name,password_hash,role,totp_enabled,active,must_change_password) VALUES(?,?,?,?,0,1,1)').run(loginId,name,bcrypt.hashSync(password,12),roleName);audit(req,'CREATE','admin',r.lastInsertRowid,loginId);flash(req,'success','Admin baru dibuat. Saat login pertama, admin wajib memasang 2FA sendiri.');}catch(e){flash(req,'error',String(e.message).includes('UNIQUE')?'ID login sudah digunakan.':e.message);}res.redirect('/admins');
});
app.post('/admins/:id/reset-password',auth,role('owner'),(req,res)=>{
  const password=req.body.password||''; if(password.length<8){flash(req,'error','Password baru minimal 8 karakter.');return res.redirect('/admins');}
  const target=db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id); if(!target){flash(req,'error','Admin tidak ditemukan.');return res.redirect('/admins');}
  db.prepare('UPDATE users SET password_hash=?,must_change_password=1,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(bcrypt.hashSync(password,12),target.id); audit(req,'RESET_PASSWORD','admin',target.id,target.login_id); flash(req,'success',`Password ${target.login_id} berhasil direset.`); res.redirect('/admins');
});
app.post('/admins/:id/reset-2fa',auth,role('owner'),(req,res)=>{
  const target=db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id); if(!target){flash(req,'error','Admin tidak ditemukan.');return res.redirect('/admins');}
  db.prepare('UPDATE users SET totp_secret=NULL,totp_enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(target.id); audit(req,'RESET_2FA','admin',target.id,target.login_id); flash(req,'success',`2FA ${target.login_id} direset. Admin akan scan QR baru saat login.`); res.redirect('/admins');
});
app.post('/admins/:id/toggle',auth,role('owner'),(req,res)=>{
  const target=db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id); if(!target||target.role==='owner'){flash(req,'error','Super Admin tidak dapat dinonaktifkan.');return res.redirect('/admins');}
  db.prepare('UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(target.id); audit(req,'TOGGLE_ADMIN','admin',target.id,target.login_id); flash(req,'success','Status admin diperbarui.'); res.redirect('/admins');
});

// generic master routes
app.get('/offices',auth,(req,res)=>res.render('offices',{items:db.prepare('SELECT * FROM offices ORDER BY active DESC,name').all()}));
app.post('/offices',auth,role('owner','admin'),(req,res)=>{try{const r=db.prepare('INSERT INTO offices(name,address,country,city,manager) VALUES(?,?,?,?,?)').run(req.body.name,req.body.address,req.body.country,req.body.city,req.body.manager);audit(req,'CREATE','office',r.lastInsertRowid,req.body.name);flash(req,'success','Kantor berhasil ditambahkan.');}catch(e){flash(req,'error',e.message);}res.redirect('/offices');});
app.post('/offices/:id/toggle',auth,role('owner','admin'),(req,res)=>{db.prepare('UPDATE offices SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?').run(req.params.id);res.redirect('/offices');});
app.get('/groups',auth,(req,res)=>res.render('groups',{items:db.prepare('SELECT g.*,o.name office_name FROM groups_tbl g LEFT JOIN offices o ON o.id=g.office_id ORDER BY g.active DESC,g.name').all(),offices:db.prepare('SELECT * FROM offices WHERE active=1 ORDER BY name').all()}));
app.post('/groups',auth,role('owner','admin'),(req,res)=>{try{const r=db.prepare('INSERT INTO groups_tbl(office_id,name,description) VALUES(?,?,?)').run(req.body.office_id||null,req.body.name,req.body.description);audit(req,'CREATE','group',r.lastInsertRowid,req.body.name);flash(req,'success','Group berhasil ditambahkan.');}catch(e){flash(req,'error',e.message);}res.redirect('/groups');});
app.post('/groups/:id/toggle',auth,role('owner','admin'),(req,res)=>{db.prepare('UPDATE groups_tbl SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?').run(req.params.id);res.redirect('/groups');});


// Edit, hapus, dan detail kantor/group
app.get('/offices/:id',auth,(req,res)=>{
  const office=db.prepare('SELECT * FROM offices WHERE id=?').get(req.params.id);
  if(!office) return res.status(404).render('error',{message:'Kantor tidak ditemukan'});
  const groups=db.prepare(`SELECT g.*,COUNT(s.id) staff_count FROM groups_tbl g LEFT JOIN staff s ON s.group_id=g.id AND s.employment_status='ACTIVE' WHERE g.office_id=? GROUP BY g.id ORDER BY g.name`).all(office.id);
  const staff=db.prepare(`SELECT s.*,g.name group_name FROM staff s LEFT JOIN groups_tbl g ON g.id=s.group_id WHERE s.office_id=? ORDER BY g.name,s.name`).all(office.id);
  res.render('office-detail',{office,groups,staff});
});
app.post('/offices/:id/edit',auth,role('owner','admin'),(req,res)=>{
  db.prepare('UPDATE offices SET name=?,address=?,country=?,city=?,manager=? WHERE id=?').run(req.body.name,req.body.address,req.body.country,req.body.city,req.body.manager,req.params.id);
  audit(req,'UPDATE','office',req.params.id,req.body.name); flash(req,'success','Kantor berhasil diperbarui.'); res.redirect('/offices');
});
app.post('/offices/:id/delete',auth,role('owner'),(req,res)=>{
  const c=db.prepare('SELECT COUNT(*) c FROM staff WHERE office_id=?').get(req.params.id).c;
  const g=db.prepare('SELECT COUNT(*) c FROM groups_tbl WHERE office_id=?').get(req.params.id).c;
  if(c||g){flash(req,'error','Kantor tidak bisa dihapus karena masih memiliki group atau staf. Pindahkan data terlebih dahulu.');return res.redirect('/offices');}
  db.prepare('DELETE FROM offices WHERE id=?').run(req.params.id); audit(req,'DELETE','office',req.params.id); flash(req,'success','Kantor berhasil dihapus.');res.redirect('/offices');
});
app.post('/groups/:id/edit',auth,role('owner','admin'),(req,res)=>{
  db.prepare('UPDATE groups_tbl SET office_id=?,name=?,description=? WHERE id=?').run(req.body.office_id||null,req.body.name,req.body.description,req.params.id);
  audit(req,'UPDATE','group',req.params.id,req.body.name);flash(req,'success','Group berhasil diperbarui.');res.redirect('/groups');
});
app.post('/groups/:id/delete',auth,role('owner'),(req,res)=>{
  const c=db.prepare('SELECT COUNT(*) c FROM staff WHERE group_id=?').get(req.params.id).c;
  if(c){flash(req,'error','Group tidak bisa dihapus karena masih memiliki staf. Pindahkan staf terlebih dahulu.');return res.redirect('/groups');}
  db.prepare('DELETE FROM groups_tbl WHERE id=?').run(req.params.id);audit(req,'DELETE','group',req.params.id);flash(req,'success','Group berhasil dihapus.');res.redirect('/groups');
});

app.post('/documents',auth,role('owner','admin','hr'),upload.single('file'),(req,res)=>{
  const type=req.body.doc_type;
  if(!['PASSPORT','VISA','WP','CONTRACT'].includes(type)) return res.status(400).render('error',{message:'Jenis dokumen tidak valid'});
  const r=db.prepare(`INSERT INTO documents(staff_id,doc_type,doc_number,issued_date,expiry_date,file_path,notes,process_status,process_note,agent_name,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`).run(req.body.staff_id,type,req.body.doc_number,req.body.issued_date||null,req.body.expiry_date,req.file?`/uploads/${req.file.filename}`:null,req.body.notes,req.body.process_status||'ACTIVE',req.body.process_note||null,req.body.agent_name||null);
  audit(req,'CREATE','document',r.lastInsertRowid,type);generateExpiryNotifications();flash(req,'success','Data dokumen berhasil ditambahkan.');
  res.redirect('/documents/'+({PASSPORT:'passport',VISA:'visa',WP:'wp',CONTRACT:'contract'}[type]));
});
app.post('/documents/:id/status',auth,role('owner','admin','hr'),(req,res)=>{
  const d=db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id); if(!d)return res.redirect('/dashboard');
  db.prepare('UPDATE documents SET process_status=?,process_note=?,agent_name=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(req.body.process_status,req.body.process_note,req.body.agent_name,req.params.id);
  audit(req,'DOCUMENT_STATUS','document',req.params.id,`${req.body.process_status}: ${req.body.process_note||''}`);
  createNotification('DOCUMENT_STATUS','Status dokumen diperbarui',`${staffName(d.staff_id)} • ${d.doc_type} • ${req.body.process_status}${req.body.process_note?' • '+req.body.process_note:''}`,'INFO','document',d.id,`docstatus-${d.id}-${Date.now()}`);
  flash(req,'success','Keterangan proses dokumen diperbarui.');res.redirect(req.get('referer')||'/dashboard');
});
app.post('/documents/:id/renew',auth,role('owner','admin','hr'),upload.single('file'),(req,res)=>{
  const d=db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id); if(!d)return res.redirect('/dashboard');
  db.prepare(`UPDATE documents SET doc_number=?,issued_date=?,expiry_date=?,file_path=COALESCE(?,file_path),notes=?,process_status='ACTIVE',process_note=?,agent_name=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(req.body.doc_number||d.doc_number,req.body.issued_date||d.issued_date,req.body.expiry_date,req.file?`/uploads/${req.file.filename}`:null,req.body.notes||d.notes,req.body.process_note||'Dokumen sudah diperpanjang dan masa aktif terbaru disimpan.',req.body.agent_name||d.agent_name,d.id);
  audit(req,'RENEW','document',d.id,req.body.expiry_date);createNotification('DOCUMENT','Dokumen berhasil diperpanjang',`${staffName(d.staff_id)} • ${d.doc_type} • masa aktif terbaru sampai ${fmtDate(req.body.expiry_date)}`,'INFO','document',d.id,`renew-${d.id}-${req.body.expiry_date}`);flash(req,'success','Masa aktif terbaru berhasil disimpan.');res.redirect(req.get('referer')||'/dashboard');
});

app.get('/former-employees',auth,(req,res)=>{
  const items=db.prepare(`SELECT f.*,s.name,s.staff_code,s.phone,s.telegram,s.shift,s.duty,s.position,o.name office_name,g.name group_name,(SELECT COUNT(*) FROM warnings w WHERE w.staff_id=s.id) warning_count FROM former_employees f JOIN staff s ON s.id=f.staff_id LEFT JOIN offices o ON o.id=s.office_id LEFT JOIN groups_tbl g ON g.id=s.group_id ORDER BY date(f.last_work_date) DESC`).all();
  res.render('former-list',{items});
});
app.get('/blacklists',auth,(req,res)=>{
  const items=db.prepare(`SELECT b.*,s.name,s.staff_code,s.phone,s.telegram,s.shift,s.duty,s.position,s.employment_status,o.name office_name,g.name group_name,(SELECT COUNT(*) FROM warnings w WHERE w.staff_id=s.id) warning_count FROM blacklists b JOIN staff s ON s.id=b.staff_id LEFT JOIN offices o ON o.id=s.office_id LEFT JOIN groups_tbl g ON g.id=s.group_id ORDER BY b.id DESC`).all();
  res.render('blacklist-list',{items});
});

app.get('/staff',auth,(req,res)=>{
  const q=(req.query.q||'').trim(); const status=req.query.status||'ACTIVE';
  let sql=`SELECT s.*,o.name office_name,g.name group_name,(SELECT COUNT(*) FROM warnings w WHERE w.staff_id=s.id) warning_count,(SELECT level FROM blacklists b WHERE b.staff_id=s.id) blacklist_level FROM staff s LEFT JOIN offices o ON o.id=s.office_id LEFT JOIN groups_tbl g ON g.id=s.group_id WHERE s.employment_status=?`;
  const params=[status]; if(q){sql+=' AND (s.name LIKE ? OR s.staff_code LIKE ? OR s.duty LIKE ?)';params.push(`%${q}%`,`%${q}%`,`%${q}%`);} sql+=' ORDER BY s.name';
  res.render('staff-list',{items:db.prepare(sql).all(...params),q,status});
});
app.get('/staff/new',auth,role('owner','admin','hr'),(req,res)=>res.render('staff-form',{staff:null,offices:db.prepare('SELECT * FROM offices WHERE active=1 ORDER BY name').all(),groups:db.prepare('SELECT * FROM groups_tbl WHERE active=1 ORDER BY name').all()}));
app.post('/staff',auth,role('owner','admin','hr'),(req,res)=>{try{const code=req.body.staff_code||`STF-${String((db.prepare('SELECT COALESCE(MAX(id),0)+1 n FROM staff').get().n)).padStart(4,'0')}`;const r=db.prepare(`INSERT INTO staff(staff_code,name,phone,telegram,office_id,group_id,shift,duty,position,start_date,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(code,req.body.name,req.body.phone,req.body.telegram,req.body.office_id||null,req.body.group_id||null,req.body.shift,req.body.duty,req.body.position,req.body.start_date||null,req.body.notes);audit(req,'CREATE','staff',r.lastInsertRowid,code);flash(req,'success','Staf berhasil ditambahkan.');res.redirect(`/staff/${r.lastInsertRowid}`);}catch(e){flash(req,'error',e.message);res.redirect('/staff/new');}});
app.get('/staff/:id',auth,(req,res)=>{const s=db.prepare(`SELECT s.*,o.name office_name,g.name group_name FROM staff s LEFT JOIN offices o ON o.id=s.office_id LEFT JOIN groups_tbl g ON g.id=s.group_id WHERE s.id=?`).get(req.params.id);if(!s)return res.status(404).render('error',{message:'Staf tidak ditemukan'});res.render('staff-detail',{staff:s,documents:db.prepare('SELECT * FROM documents WHERE staff_id=? ORDER BY expiry_date').all(s.id),leaves:db.prepare('SELECT * FROM leave_requests WHERE staff_id=? ORDER BY start_date DESC').all(s.id),warnings:db.prepare('SELECT * FROM warnings WHERE staff_id=? ORDER BY warning_date DESC').all(s.id),former:db.prepare('SELECT * FROM former_employees WHERE staff_id=?').get(s.id),blacklist:db.prepare('SELECT * FROM blacklists WHERE staff_id=?').get(s.id)});});
app.get('/staff/:id/edit',auth,role('owner','admin','hr'),(req,res)=>res.render('staff-form',{staff:db.prepare('SELECT * FROM staff WHERE id=?').get(req.params.id),offices:db.prepare('SELECT * FROM offices WHERE active=1 ORDER BY name').all(),groups:db.prepare('SELECT * FROM groups_tbl WHERE active=1 ORDER BY name').all()}));
app.post('/staff/:id',auth,role('owner','admin','hr'),(req,res)=>{db.prepare(`UPDATE staff SET name=?,phone=?,telegram=?,office_id=?,group_id=?,shift=?,duty=?,position=?,start_date=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(req.body.name,req.body.phone,req.body.telegram,req.body.office_id||null,req.body.group_id||null,req.body.shift,req.body.duty,req.body.position,req.body.start_date||null,req.body.notes,req.params.id);audit(req,'UPDATE','staff',req.params.id);flash(req,'success','Data staf diperbarui.');res.redirect(`/staff/${req.params.id}`);});

app.post('/staff/:id/documents',auth,role('owner','admin','hr'),upload.single('file'),(req,res)=>{const r=db.prepare('INSERT INTO documents(staff_id,doc_type,doc_number,issued_date,expiry_date,file_path,notes) VALUES(?,?,?,?,?,?,?)').run(req.params.id,req.body.doc_type,req.body.doc_number,req.body.issued_date||null,req.body.expiry_date,req.file?`/uploads/${req.file.filename}`:null,req.body.notes);audit(req,'CREATE','document',r.lastInsertRowid,req.body.doc_type);generateExpiryNotifications();flash(req,'success','Dokumen berhasil disimpan.');res.redirect(`/staff/${req.params.id}`);});
app.post('/documents/:id/delete',auth,role('owner','admin','hr'),(req,res)=>{const d=db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);if(d){db.prepare('DELETE FROM documents WHERE id=?').run(d.id);audit(req,'DELETE','document',d.id);flash(req,'success','Dokumen dihapus.');return res.redirect(`/staff/${d.staff_id}`);}res.redirect('/staff');});

app.post('/staff/:id/warnings',auth,role('owner','admin','hr','leader'),(req,res)=>{const r=db.prepare('INSERT INTO warnings(staff_id,level,warning_date,reason,details,valid_until,status,created_by) VALUES(?,?,?,?,?,?,?,?)').run(req.params.id,req.body.level,req.body.warning_date,req.body.reason,req.body.details,req.body.valid_until||null,'ACTIVE',req.session.user.name);audit(req,'CREATE','warning',r.lastInsertRowid,req.body.level);createNotification('SP',`SP baru: ${req.body.level}`,`${staffName(req.params.id)} mendapatkan ${req.body.level}: ${req.body.reason}`,'HIGH','staff',req.params.id,`sp-${r.lastInsertRowid}`);flash(req,'success','SP berhasil dicatat.');res.redirect(`/staff/${req.params.id}`);});
app.post('/staff/:id/former',auth,role('owner','admin','hr'),(req,res)=>{db.exec('BEGIN');try{db.prepare("UPDATE staff SET employment_status='FORMER',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(req.params.id);db.prepare('INSERT OR REPLACE INTO former_employees(staff_id,last_work_date,exit_type,exit_reason,rehire_eligible,notes,created_by) VALUES(?,?,?,?,?,?,?)').run(req.params.id,req.body.last_work_date,req.body.exit_type,req.body.exit_reason,req.body.rehire_eligible?1:0,req.body.notes,req.session.user.name);db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}audit(req,'MOVE_TO_FORMER','staff',req.params.id,req.body.exit_reason);createNotification('FORMER','Staf menjadi ex karyawan',`${staffName(req.params.id)} tidak bekerja lagi. Alasan: ${req.body.exit_reason}`,'HIGH','staff',req.params.id,`former-${req.params.id}`);flash(req,'success','Staf dipindahkan ke Ex Karyawan.');res.redirect(`/staff/${req.params.id}`);});
app.post('/staff/:id/blacklist',auth,role('owner','admin','hr'),(req,res)=>{db.prepare('INSERT OR REPLACE INTO blacklists(staff_id,level,reason,permanent,review_date,created_by) VALUES(?,?,?,?,?,?)').run(req.params.id,req.body.level,req.body.reason,req.body.permanent?1:0,req.body.review_date||null,req.session.user.name);audit(req,'BLACKLIST','staff',req.params.id,req.body.reason);createNotification('BLACKLIST','Staf masuk blacklist',`${staffName(req.params.id)} masuk blacklist ${req.body.level}. Alasan: ${req.body.reason}`,'CRITICAL','staff',req.params.id,`blacklist-${req.params.id}`);flash(req,'success','Blacklist berhasil disimpan.');res.redirect(`/staff/${req.params.id}`);});
app.post('/staff/:id/blacklist/remove',auth,role('owner'),(req,res)=>{db.prepare('DELETE FROM blacklists WHERE staff_id=?').run(req.params.id);audit(req,'REMOVE_BLACKLIST','staff',req.params.id);flash(req,'success','Blacklist dicabut.');res.redirect(`/staff/${req.params.id}`);});

app.get('/leave',auth,(req,res)=>{const status=req.query.status||'ALL';let sql=`SELECT l.*,s.name,s.staff_code,o.name office_name,g.name group_name FROM leave_requests l JOIN staff s ON s.id=l.staff_id LEFT JOIN offices o ON o.id=s.office_id LEFT JOIN groups_tbl g ON g.id=s.group_id`;const p=[];if(status!=='ALL'){sql+=' WHERE l.status=?';p.push(status);}sql+=' ORDER BY date(l.start_date) DESC';res.render('leave',{items:db.prepare(sql).all(...p),staff:db.prepare("SELECT id,name,staff_code FROM staff WHERE employment_status='ACTIVE' ORDER BY name").all(),status});});
app.post('/leave',auth,role('owner','admin','hr','leader'),(req,res)=>{const r=db.prepare('INSERT INTO leave_requests(staff_id,start_date,end_date,leave_type,replacement_staff,reason,status) VALUES(?,?,?,?,?,?,?)').run(req.body.staff_id,req.body.start_date,req.body.end_date,req.body.leave_type,req.body.replacement_staff,req.body.reason,'PENDING');audit(req,'CREATE','leave',r.lastInsertRowid);flash(req,'success','Pengajuan cuti dibuat.');res.redirect('/leave');});
app.post('/leave/:id/status',auth,role('owner','admin','hr','leader'),(req,res)=>{const status=req.body.status;db.prepare('UPDATE leave_requests SET status=?,approved_by=?,approved_at=CURRENT_TIMESTAMP WHERE id=?').run(status,req.session.user.name,req.params.id);const l=db.prepare('SELECT l.*,s.name FROM leave_requests l JOIN staff s ON s.id=l.staff_id WHERE l.id=?').get(req.params.id);audit(req,'LEAVE_STATUS','leave',req.params.id,status);if(status==='APPROVED')createNotification('LEAVE','Cuti disetujui',`${l.name}: ${fmtDate(l.start_date)} sampai ${fmtDate(l.end_date)}`,'INFO','leave',l.id,`leave-approved-${l.id}`);flash(req,'success',`Status cuti menjadi ${status}.`);res.redirect('/leave');});
app.get('/leave/upcoming',auth,(req,res)=>{const office=req.query.office||'';const group=req.query.group||'';let sql=`SELECT l.*,s.name,s.staff_code,s.shift,s.duty,o.name office_name,g.name group_name FROM leave_requests l JOIN staff s ON s.id=l.staff_id LEFT JOIN offices o ON o.id=s.office_id LEFT JOIN groups_tbl g ON g.id=s.group_id WHERE l.status='APPROVED' AND date(l.end_date)>=date('now')`;const p=[];if(office){sql+=' AND s.office_id=?';p.push(office);}if(group){sql+=' AND s.group_id=?';p.push(group);}sql+=' ORDER BY date(l.start_date),s.name';res.render('leave-upcoming',{items:db.prepare(sql).all(...p),offices:db.prepare('SELECT * FROM offices WHERE active=1 ORDER BY name').all(),groups:db.prepare('SELECT * FROM groups_tbl WHERE active=1 ORDER BY name').all(),office,group});});

app.get('/notifications',auth,(req,res)=>res.render('notifications',{items:db.prepare('SELECT * FROM notifications ORDER BY is_read ASC,id DESC LIMIT 200').all()}));
app.post('/notifications/:id/read',auth,(req,res)=>{db.prepare('UPDATE notifications SET is_read=1 WHERE id=?').run(req.params.id);res.redirect(req.get('referer')||'/notifications');});
app.post('/notifications/read-all',auth,(req,res)=>{db.prepare('UPDATE notifications SET is_read=1').run();res.redirect('/notifications');});
app.get('/audit',auth,role('owner','admin'),(req,res)=>res.render('audit',{items:db.prepare('SELECT a.*,u.name user_name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 300').all()}));

function staffName(id){return db.prepare('SELECT name FROM staff WHERE id=?').get(id)?.name||'Staf';}
function createNotification(category,title,message,severity='INFO',entityType=null,entityId=null,dedupeKey=null){try{db.prepare('INSERT INTO notifications(category,title,message,severity,entity_type,entity_id,dedupe_key) VALUES(?,?,?,?,?,?,?)').run(category,title,message,severity,entityType,entityId,dedupeKey);sendTelegram(`*${title}*\n${message}`);}catch(e){if(!String(e.message).includes('UNIQUE'))console.error(e);}}
function threshold(type){return type==='PASSPORT'?270:(type==='VISA'||type==='WP'?60:30);}
function generateExpiryNotifications(){
  const rows=db.prepare(`SELECT d.*,s.name,s.staff_code,o.name office_name,g.name group_name FROM documents d JOIN staff s ON s.id=d.staff_id LEFT JOIN offices o ON o.id=s.office_id LEFT JOIN groups_tbl g ON g.id=s.group_id WHERE s.employment_status='ACTIVE'`).all();
  for(const d of rows){const left=daysUntil(d.expiry_date),limit=threshold(d.doc_type);if(left<=limit){const sev=left<0?'CRITICAL':left<=7?'CRITICAL':left<=30?'HIGH':'WARNING';const label={PASSPORT:'Paspor',VISA:'Visa',WP:'Work Permit',CONTRACT:'Kontrak'}[d.doc_type];createNotification('DOCUMENT',`${label} ${left<0?'kedaluwarsa':'akan habis'}`,`${d.name} (${d.staff_code}) • ${d.office_name||'-'} / ${d.group_name||'-'} • berakhir ${fmtDate(d.expiry_date)} • sisa ${left} hari`,sev,'document',d.id,`doc-${d.id}-${left}`);}}
}
async function sendTelegram(text){const token=env('TELEGRAM_BOT_TOKEN'),chat=env('TELEGRAM_CHAT_ID');if(!token||!chat)return;try{await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:chat,text,parse_mode:'Markdown'})});}catch(e){console.error('Telegram:',e.message);}}
cron.schedule('5 8 * * *',()=>{generateExpiryNotifications(); const leaves=db.prepare(`SELECT l.*,s.name FROM leave_requests l JOIN staff s ON s.id=l.staff_id WHERE l.status='APPROVED' AND date(l.start_date) BETWEEN date('now') AND date('now','+7 day') ORDER BY l.start_date`).all(); if(leaves.length)sendTelegram(`*Jadwal Cuti Mendatang*\n${leaves.map(x=>`• ${x.name}: ${fmtDate(x.start_date)} - ${fmtDate(x.end_date)}`).join('\n')}`);},{timezone:TZ});

app.use((err,req,res,next)=>{console.error(err);res.status(500).render('error',{message:process.env.NODE_ENV==='production'?'Terjadi kesalahan pada server.':err.message});});
app.listen(PORT,'0.0.0.0',()=>console.log(`${APP_NAME} running on port ${PORT}`));
