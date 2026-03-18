const express = require('express');
const app = express();
const http = require('http').createServer(app);
const { Server } = require("socket.io");
const io = new Server(http);
const bodyParser = require('body-parser');
const MongoClient = require('mongodb').MongoClient;
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const nodemailer = require('nodemailer');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs/promises');
require('dotenv').config();
const verificationCodes = new Map();
// ========== 기본 설정 ==========
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(flash());
app.use(cookieParser());

// ========== Rate limiting (auth/email sensitive routes) ==========
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});
const emailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

// ========== CSRF protection (simple double-submit via session) ==========
function ensureCsrfToken(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return next();
}

function renderWithCsrf(view) {
  return (req, res) => {
    res.render(view, { csrfToken: req.session.csrfToken });
  };
}

function requireCsrf(req, res, next) {
  const token =
    req.headers['x-csrf-token'] ||
    req.headers['x-xsrf-token'] ||
    (req.body && req.body._csrf);

  if (!token || token !== req.session.csrfToken) {
    return res.status(403).send('Invalid CSRF token');
  }
  return next();
}

// ========== 세션 설정 ==========
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-key-in-production',
  resave: true,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  },
}));

// ========== Passport 초기화 ==========
app.use(passport.initialize());
app.use(passport.session());

// ========== 파일 업로드 설정 ==========
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, './public/image'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    const safeExt = ['.png', '.jpg', '.jpeg', '.gif', '.webp'].includes(ext) ? ext : '';
    const name = crypto.randomBytes(16).toString('hex') + safeExt;
    cb(null, name);
  }
});
const upload = multer({
  storage,
  limits: {
    files: 10,
    fileSize: 5 * 1024 * 1024, // 5MB per file
  },
  fileFilter: (req, file, cb) => {
    const ok = typeof file.mimetype === 'string' && file.mimetype.startsWith('image/');
    cb(ok ? null : new Error('Only image uploads are allowed'), ok);
  },
});

// ========== 로그인 확인 미들웨어 ==========
function 로그인(req, res, next) {
  if (req.isAuthenticated?.() || req.session.user) {
    return next(); // 로그인되어 있으면 다음으로
  }
  console.log('⛔ 로그인되지 않은 접근');
  req.flash('error', '로그인이 필요합니다.');
  return res.redirect('/login'); // 로그인 페이지로 이동
}

// ========== MongoDB 연결 ==========
let db;
MongoClient.connect(process.env.DB_URL, { useUnifiedTopology: true }, (err, client) => {
  if (err) return console.log(err);
  db = client.db('server');
  console.log('MongoDB Connected');
});
// ===== 이메일 전송 설정 =====
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.naver.com',
  port: parseInt(process.env.EMAIL_PORT) || 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});
// ========== Passport LocalStrategy (Debug Logging Added) ==========
passport.use(new LocalStrategy({
  usernameField: 'id',
  passwordField: 'pw',
  session: true
}, (id, pw, done) => {

  console.log(" [DEBUG] LocalStrategy 호출됨");
  console.log(" 입력받은 ID:", id);

  db.collection('login').findOne({ id }, async (err, user) => {

    console.log(" [DEBUG] DB에서 조회 시도: id =", id);

    if (err) {
      console.log(" [DEBUG] DB 조회 중 오류 발생:", err);
      return done(err);
    }

    if (!user) {
      console.log(" [DEBUG] 아이디 없음:", id);
      return done(null, false, { message: '존재하지 않는 아이디입니다.' });
    }

    console.log("[DEBUG] DB 조회 성공");

    // 비밀번호 비교
    try {
      const match = await bcrypt.compare(pw, user.pw);
      console.log("[DEBUG] 비밀번호 비교 결과:", match);

      if (match) {
        console.log("[DEBUG] 로그인 성공:", user.id);
        return done(null, user);
      } else {
        console.log("[DEBUG] 비밀번호 불일치");
        return done(null, false, { message: '비밀번호가 일치하지 않습니다.' });
      }
    } catch (error) {
      console.log("[DEBUG] 비밀번호 비교 중 오류:", error);
      return done(error);
    }
  });
}));
// ========== serializeUser ==========
passport.serializeUser((user, done) => {
  console.log("[DEBUG] serializeUser 실행됨");
  console.log("저장할 user.id:", user.id);
  done(null, user.id);
});


// ========== deserializeUser ==========
passport.deserializeUser((id, done) => {
  console.log("[DEBUG] deserializeUser 실행됨 - 찾는 ID:", id);

  db.collection('login').findOne({ id }, (err, user) => {
    if (err) {
      console.log("[DEBUG] deserializeUser DB 에러:", err);
      return done(err);
    }
    console.log("[DEBUG] deserializeUser 조회된 user:", user);
    done(err, user);
  });
})
// ========== 라우팅 ==========
app.get('/', ensureCsrfToken, renderWithCsrf('login.ejs'));
app.get('/login', ensureCsrfToken, renderWithCsrf('login.ejs'));
app.get('/signup', ensureCsrfToken, renderWithCsrf('signup.ejs'));
app.get('/main', (req, res) => res.render('index.ejs'));
app.get('/reset-password', ensureCsrfToken, renderWithCsrf('reset-password.ejs'));
app.get('/findid', ensureCsrfToken, renderWithCsrf('findid.ejs'));

// 게시글 수정 (작성자만)
app.get('/edit/:id', 로그인, ensureCsrfToken, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).send('잘못된 요청');
  const user = req.session.user;
  const post = await db.collection('post').findOne({ _id: id });
  if (!post) return res.status(404).send('게시물을 찾을 수 없습니다.');
  if (!user?.id || post.작성자_id !== user.id) return res.status(403).send('권한이 없습니다.');
  return res.render('edit.ejs', { post, csrfToken: req.session.csrfToken });
});
app.post('/edit/:id', 로그인, requireCsrf, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).send('잘못된 요청');
  const user = req.session.user;
  if (!user?.id) return res.status(401).send('로그인이 필요합니다.');
  const { title, content } = req.body || {};
  const result = await db.collection('post').updateOne(
    { _id: id, 작성자_id: user.id },
    { $set: { 제목: title, 내용: content } }
  );
  if (!result?.matchedCount) return res.status(403).send('권한이 없습니다.');
  return res.redirect('/detail/' + id);
});
// ========== 비밀번호 초기화 ================================
app.post('/reset-password', requireCsrf, emailLimiter, async (req, res) => {
  const { email } = req.body;
  const user = await db.collection('login').findOne({ em: email });

  if (!user) return res.json({ success: false });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  verificationCodes.set(email, code);

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: '비밀번호 재설정 인증 코드',
      text: `인증 코드: ${code}`
    });

    res.json({ success: true });
  } catch (err) {
    console.error('메일 전송 오류:', err);
    res.status(500).json({ success: false });
  }
});

// ========== 인증코드 검증 ==================================
app.post('/verify-code', requireCsrf, authLimiter, (req, res) => {
  const { email, code } = req.body;

  const savedCode = verificationCodes.get(email);

  if (savedCode && savedCode === code) {
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

// ========== 새 비밀번호 저장 ==================================
app.post('/reset-password-new', requireCsrf, authLimiter, async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.collection('login').updateOne(
      { em: email },
      { $set: { pw: hashedPassword } }
    );

    // 인증코드 사용 후 즉시 삭제
    verificationCodes.delete(email);

    res.json({ success: true });
  } catch (err) {
    console.error('비밀번호 변경 오류:', err);
    res.status(500).json({ success: false });
  }
});
// ========== 아이디 존재 확인 (이메일 없이 id 기반) ==========
app.post('/findid', requireCsrf, authLimiter, async (req, res) => {
  const em = req.body.em; // 사용자가 입력한 이메일

  try {
    const user = await db.collection('login').find({ em }).toArray(); // 이메일로 검색

    if (user.length > 0) {
      const ids = user.map(u => u.id);
      res.json({ success: true, ids });
    } else {
      res.json({ success: false, message: '해당 메일로 등록된 아이디가 없습니다.' });
    }
  } catch (err) {
    console.error('아이디 찾기 오류:', err);
    res.status(500).json({ success: false, error: '서버 오류' });
  }
});
// ========== 회원가입 ==========
app.post('/signup', requireCsrf, authLimiter, async (req, res) => {
  const { id, pw, em, nm } = req.body;
  try {
    const exists = await db.collection('login').findOne({ id });
    if (exists) return res.send('이미 사용 중인 아이디입니다.');
    const hashed = await bcrypt.hash(pw, 10);
    await db.collection('login').insertOne({ id, pw: hashed, em, nm });
    res.redirect('/login');
  } catch (e) {
    console.error(e);
    res.status(500).send('회원가입 실패');
  }
});

// ========== 로그인 ==========
app.post('/login', requireCsrf, authLimiter, (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      console.error(err);
      return next(err);
    }

    if (!user) {
      // 로그인 실패
      return res.redirect('/login?error=1');
    }

    // 로그인 성공 → 세션에 저장
    req.logIn(user, (err) => {
      if (err) return next(err);

      req.session.user = {
        id: user.id,
        nm: user.nm
      };

      console.log('로그인 성공', req.session.user);
      return res.redirect('/list');
    });
  })(req, res, next);
});


// ========== 로그아웃 ==========
app.get('/logout', (req, res, next) => {
  if (req.isAuthenticated?.()) {
    req.logout(err => {
      if (err) return next(err);
      req.session.destroy();
      res.redirect('/login');
    });
  } else {
    req.session.destroy();
    res.redirect('/login');
  }
});

// ========== 마이페이지 (로그인 필요) ==========
app.get('/mypage', 로그인, (req, res) => {
  const user = req.user || req.session.user;
  res.render('mypage.ejs', { user });  // 
});

// ========== 게시판 기능 ==========
app.get('/list', 로그인, ensureCsrfToken, (req, res) => {
  db.collection('post').find().toArray((err, result) => {
    res.render('list.ejs', { posts: result, user: req.session.user, csrfToken: req.session.csrfToken });
  });
});

// ========== 게시물 작성 페이지 핸들링 =============
app.get('/write', 로그인, ensureCsrfToken, renderWithCsrf('write.ejs'));
// =========== 게시물 작성 핸들링 ===============
app.post('/add', 로그인, requireCsrf, (req, res) => {
  db.collection('counter').findOne({ name: '게시물갯수' }, (err, result) => {
    if (err) return res.json({ success: false });
    const now = new Date();
    const kstDate = new Date(now.getTime() + 9 * 60 * 60 * 1000);

    // 포맷팅
    const formattedDate = kstDate.toISOString().slice(0, 19).replace('T', ' ');

    // 로컬/신규 DB에서는 counter 문서가 없을 수 있음 → 없으면 0부터 시작
    const 총게시물갯수 = (result && typeof result.toTalPost === 'number') ? result.toTalPost : 0;
    const nextId = 총게시물갯수 + 1;

    const 저장할거 = {
      _id: nextId,
      제목: req.body.title,
      내용: req.body.content,
      작성자: req.session.user.nm,
      작성자_id: req.session.user.id,
      날짜: formattedDate // 여기서 날짜와 시간 저장
    };

    db.collection('post').insertOne(저장할거, (err) => {
      if (err) return res.json({ success: false });

      // counter 문서가 없으면 생성하고 증가 (upsert)
      db.collection('counter').updateOne(
        { name: '게시물갯수' },
        { $inc: { toTalPost: 1 } },
        { upsert: true },
        (err) => {
          if (err) return res.json({ success: false });

          // JSON으로 성공 메시지 전달
          res.json({ success: true, redirect: '/list' });
        }
      );
    });
  });
});
/* ================== 3. 대댓글 작성 ================== */
app.post('/comment/reply', requireCsrf, async (req, res) => {
  try {
    const { postId, parentId, content } = req.body;


    if (!req.session.user)
      return res.json({ success: false, message: '로그인이 필요합니다.' });


    const now = new Date();
    const kst = new Date(now.getTime() + 9 * 60 * 60 * 1000);


    await db.collection('comments').insertOne({
      postId: parseInt(postId),
      content,
      writer: req.session.user.nm,
      writer_id: req.session.user.id,
      date: kst.toISOString().slice(0, 19).replace('T', ' '),
      parentId: parseInt(parentId) // 어떤 댓글에 대한 답글인지
    });


    res.json({ success: true });
  } catch (err) {
    console.log(err);
    res.json({ success: false });
  }
});
// ================= 게시물 댓글 작성 ============================
app.post('/comment/add', requireCsrf, async (req, res) => {
  try {
    const { postId, content } = req.body;

    // 로그인 체크
    if (!req.session.user) {
      return res.json({
        success: false,
        message: "로그인이 필요합니다"
      });
    }

    const writer = req.session.user.nm;
    const writer_id = req.session.user.id;  

    console.log('writer:', writer, ' writer_id:', writer_id);

    // 날짜 생성 (KST 기준)
    const now = new Date();
    const kstDate = new Date(now.getTime() + 9 * 60 * 60 * 1000);
    const dateString = kstDate.toISOString().slice(0, 19).replace('T', ' ');

    await db.collection('comments').insertOne({
      postId: parseInt(postId),
      writer: writer,
      writer_id: writer_id,
      content: content,
      date: dateString
    });

    return res.json({ success: true });

  } catch (err) {   // ✅ err 추가
    console.log("댓글 저장 오류:", err);
    res.json({ success: false });
  }
});

// ================== 게시물 상세 페이지 핸들링 ===================
app.get('/detail/:id', 로그인, ensureCsrfToken, async (req, res) => {
  try {
    const postId = parseInt(req.params.id);
    const post = await db.collection('post').findOne({ _id: postId });
    if (!post) return res.status(404).send('게시물없음');
    const comments = await db.collection('comments').find({ postId }).sort({ _id: -1 }).toArray();
    res.render('detail.ejs', {
      post, comments, user: req.session.user, csrfToken: req.session.csrfToken
    });
  } catch (err) {
    console.log(err);
    res.status(500).send('서버오류');
  }
});
// ================ 게시글 삭제 ======================
// detail.ejs는 form POST를 사용하므로 POST도 지원
app.post('/delete', 로그인, requireCsrf, (req, res) => {
  const id = parseInt(req.body._id);
  if (!Number.isFinite(id)) return res.status(400).send('잘못된 요청');

  const user = req.session.user;
  if (!user?.id) return res.status(401).send('로그인이 필요합니다.');

  db.collection('post').deleteOne({ _id: id, 작성자_id: user.id }, (err, result) => {
    if (err) return res.status(500).send('서버 오류');
    if (!result?.deletedCount) return res.status(403).send('권한이 없습니다.');
    return res.redirect('/list');
  });
});
app.delete('/delete', 로그인, requireCsrf, (req, res) => {
  const id = parseInt(req.body._id);
  if (!Number.isFinite(id)) return res.status(400).send('잘못된 요청');

  const user = req.session.user;
  if (!user?.id) return res.status(401).send('로그인이 필요합니다.');

  // 작성자만 삭제 가능하도록 제한
  db.collection('post').deleteOne({ _id: id, 작성자_id: user.id }, (err, result) => {
    if (err) return res.status(500).send('서버 오류');
    if (!result?.deletedCount) return res.status(403).send('권한이 없습니다.');
    return res.send('삭제완료');
  });
});
// ================ 게시글 좋아요 ====================
app.post('/post/like', requireCsrf, async (req, res) => {
  try {
    if (!req.session.user) return res.json({ success: false, message: '로그인이 필요합니다.' });


    const { postId } = req.body;
    const userId = req.session.user.id;


    const post = await db.collection('post').findOne({ _id: parseInt(postId) });
    if (!post) return res.json({ success: false, message: '게시물이 존재하지 않습니다.' });


    const liked = post.likes && post.likes.includes(userId);


    if (liked) {
      await db.collection('post').updateOne(
        { _id: parseInt(postId) },
        { $pull: { likes: userId } }
      );
    } else {
      await db.collection('post').updateOne(
        { _id: parseInt(postId) },
        { $addToSet: { likes: userId } }
      );
    }


    res.json({ success: true, liked: !liked });
  } catch (err) {
    console.log('like error', err);
    res.json({ success: false });
  }
});
// ========== 채팅 기능 ==========
app.post('/chatroom', 로그인, (req, res) => {
  const 저장할거 = {
    title: '채팅방',
    member: [req.body.당한사람id, req.user._id],
    date: new Date()
  };
  db.collection('chatroom').insertOne(저장할거).then(() => res.send('저장완료'));
});

app.get('/chat', 로그인, (req, res) => {
  db.collection('chatroom').find({ member: req.user._id }).toArray().then(result => {
    res.render('chat.ejs', { data: result });
  });
});

app.post('/message', 로그인, (req, res) => {
  const msg = {
    parent: req.body.parent,
    userid: req.user._id,
    content: req.body.content,
    date: new Date(),
  };
  db.collection('message').insertOne(msg).then(result => res.send(result));
});

app.get('/message/:id', 로그인, (req, res) => {
  res.writeHead(200, {
    "Connection": "keep-alive",
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
  });
  db.collection('message').find({ parent: req.params.id }).toArray().then(result => {
    res.write('event: test\n');
    res.write('data:' + JSON.stringify(result) + '\n\n');
  });
  const pipeline = [{ $match: { 'fullDocument.parent': req.params.id } }];
  const collection = db.collection('message');
  const changeStream = collection.watch(pipeline);
  changeStream.on('change', (result) => {
    res.write('event: test\n');
    res.write('data: ' + JSON.stringify([result.fullDocument]) + '\n\n');
  });
});

// ========== 파일 업로드 ==========
app.get('/upload', 로그인, ensureCsrfToken, renderWithCsrf('upload.ejs'));
app.post('/upload', 로그인, requireCsrf, (req, res, next) => {
  upload.array('uploading', 10)(req, res, async (err) => {
    if (err) return next(err);
    try {
      const files = Array.isArray(req.files) ? req.files : [];
      const { fileTypeFromFile } = await import('file-type');

      for (const f of files) {
        const detected = await fileTypeFromFile(f.path);
        const ok = detected && typeof detected.mime === 'string' && detected.mime.startsWith('image/');
        if (!ok) {
          await fs.unlink(f.path).catch(() => {});
          return res.status(400).send('Invalid upload');
        }
      }
      return res.redirect('/');
    } catch (e) {
      return next(e);
    }
  });
});

// CSRF error handler (kept for compatibility)
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).send('Invalid CSRF token');
  }
  return next(err);
});

// ========== Socket.io ==========
app.get('/socket', 로그인, (req, res) => res.render('socket.ejs'));
io.on('connection', (socket) => {
  console.log('유저 접속');

  // 특정 방에 들어가기
  socket.on('joinroom', () => {
    socket.join('room1');
  });

  // 같은 방의 다른 사람에게만 메시지 전송 (본인 제외)
  socket.on('room1-send', (data) => {
    socket.broadcast.to('room1').emit('broadcast', data);
  });

  // 모든 사람에게 메시지 전송 (본인 제외)
  socket.on('user-send', (data) => {
    socket.broadcast.emit('broadcast', data);
  });
});


// ========== 서버 실행 ==========
http.listen(process.env.PORT || 3000, '0.0.0.0', () => {
  console.log(' Server running on port', process.env.PORT || 3000);
});

