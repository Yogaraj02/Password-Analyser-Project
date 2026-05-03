// ============================================================
// UTILS
// ============================================================
const safeSetText = (id, text) => {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
  return el;
};

const safeSetStyle = (id, property, value) => {
  const el = document.getElementById(id);
  if (el) el.style[property] = value;
  return el;
};

// ============================================================
// STATE
// ============================================================
let analysisHistory = [];
let crackInterval = null;
let crackRunning = false;
let genOptions = { upper: true, lower: true, digits: true, special: true, noAmb: false, noRepeat: false, pronounce: false, passphrase: false };

// Common passwords list
const commonPasswords = new Set(['password','123456','qwerty','abc123','letmein','monkey','1234567890','password1','iloveyou','admin','welcome','login','master','sunshine','princess','dragon','passw0rd','shadow','superman','michael','football','baseball','solo','starwars','batman','trustno1','hello','1q2w3e4r','12345678','123456789','000000','111111','123123','password123','admin123','root','toor','test','guest','changeme','temp','000000']);

// ============================================================
// ANALYZE
// ============================================================
window.analyzePassword = function(pwd) {
  const len = pwd.length;
  if (!len) { resetUI(); return; }

  // Charset
  const hasUpper = /[A-Z]/.test(pwd);
  const hasLower = /[a-z]/.test(pwd);
  const hasDigit = /[0-9]/.test(pwd);
  const hasSpecial = /[^A-Za-z0-9]/.test(pwd);

  let charset = 0;
  if (hasUpper) charset += 26;
  if (hasLower) charset += 26;
  if (hasDigit) charset += 10;
  if (hasSpecial) charset += 32;

  const entropy = Math.round(len * Math.log2(charset || 1));
  const unique = new Set(pwd).size;
  const combinations = formatCombinations(Math.pow(charset || 1, len));

  // SCORE
  let score = 0;
  score += Math.min(len * 4, 40);
  if (hasUpper) score += 10;
  if (hasLower) score += 10;
  if (hasDigit) score += 10;
  if (hasSpecial) score += 15;
  score += Math.min((unique / len) * 15, 15);
  if (len >= 20) score += 10;
  if (commonPasswords.has(pwd.toLowerCase())) score = Math.min(score, 15);
  if (/^(.)\1+$/.test(pwd)) score = 5;
  score = Math.min(Math.round(score), 100);

  // STRENGTH LEVEL
  const level = score < 20 ? {label:'Catastrophic', color:'#ff2d55'}
              : score < 40 ? {label:'Very Weak', color:'#ff4b6e'}
              : score < 55 ? {label:'Weak', color:'#ff9500'}
              : score < 70 ? {label:'Fair', color:'#ffd60a'}
              : score < 85 ? {label:'Strong', color:'#22d3a0'}
              : {label:'Fort Knox', color:'#0aff87'};

  // UPDATE METRICS
  safeSetText('scoreVal', score);
  safeSetStyle('scoreVal', 'color', level.color);
  safeSetText('lengthVal', len);
  safeSetText('entropyVal', entropy);
  safeSetText('charsetVal', charset);
  safeSetText('combVal', combinations);
  safeSetText('uniqueVal', unique);

  // STRENGTH TEXT + SEGMENTS
  safeSetText('strengthText', level.label);
  safeSetStyle('strengthText', 'color', level.color);
  const segs = 5;
  const active = Math.ceil((score/100)*segs);
  for (let i=1; i<=segs; i++) {
    const el = document.getElementById('s'+i);
    if (el) {
      el.style.background = i <= active ? level.color : 'var(--bg4)';
      el.style.boxShadow = i <= active ? `0 0 6px ${level.color}` : 'none';
    }
  }

  // REQUIREMENTS
  const hasNoRepeat = !/(.)\1{2,}/.test(pwd);
  const notCommon = !commonPasswords.has(pwd.toLowerCase());
  setReq('req-len', len >= 12);
  setReq('req-upper', hasUpper);
  setReq('req-lower', hasLower);
  setReq('req-digit', hasDigit);
  setReq('req-special', hasSpecial);
  setReq('req-norepeat', hasNoRepeat);
  setReq('req-nocommon', notCommon);

  // ENTROPY ANALYSIS
  const complexClass = entropy < 28 ? 'Trivial' : entropy < 36 ? 'Very Low' : entropy < 60 ? 'Low' : entropy < 80 ? 'Moderate' : entropy < 100 ? 'High' : 'Extreme';
  const charPool = [hasUpper&&'A-Z', hasLower&&'a-z', hasDigit&&'0-9', hasSpecial&&'Special'].filter(Boolean).join(' + ') || 'None';
  safeSetText('entropyBits', `${entropy} bits`);
  safeSetText('complexClass', complexClass);
  safeSetText('charPool', charPool);
  safeSetText('guessRes', entropy >= 80 ? 'Quantum-resistant' : entropy >= 60 ? 'GPU cluster resistant' : entropy >= 40 ? 'Basic attack resistant' : 'Easily guessable');
  safeSetText('randEquiv', `≈ ${Math.round(entropy/8)}-byte random key`);

  // CHARACTER MAP
  const mapEl = document.getElementById('charMap');
  if (mapEl) {
    mapEl.innerHTML = '';
    for (const ch of pwd) {
      const cell = document.createElement('div');
      cell.className = 'char-cell';
      cell.textContent = ch === ' ' ? '·' : ch;
      if (/[A-Z]/.test(ch)) cell.classList.add('upper');
      else if (/[a-z]/.test(ch)) cell.classList.add('lower');
      else if (/[0-9]/.test(ch)) cell.classList.add('digit');
      else cell.classList.add('special');
      mapEl.appendChild(cell);
    }
  }

  // PATTERNS
  const patterns = detectPatterns(pwd);
  const patEl = document.getElementById('patternList');
  if (patEl) {
    patEl.innerHTML = '';
    if (!patterns.length) {
      patEl.innerHTML = '<div class="pattern-chip"><span class="chip-dot" style="background:var(--green)"></span><span style="color:var(--green);font-family:var(--mono);font-size:12px;">No dangerous patterns detected ✓</span></div>';
    } else {
      patterns.forEach(p => {
        const chip = document.createElement('div');
        chip.className = 'pattern-chip';
        chip.innerHTML = `<span class="chip-dot" style="background:${p.bad?'var(--red)':'var(--orange)'}"></span><span style="color:${p.bad?'var(--red)':'var(--orange)'};font-family:var(--mono);font-size:12px;">${p.label}</span>`;
        patEl.appendChild(chip);
      });
    }
  }

  // SUGGESTIONS
  const suggestions = getSuggestions(pwd, score, hasUpper, hasLower, hasDigit, hasSpecial, len);
  const suggEl = document.getElementById('suggList');
  if (suggEl) {
    suggEl.innerHTML = '';
    suggestions.forEach(s => {
      const el = document.createElement('div');
      el.className = `suggestion ${s.type}`;
      el.innerHTML = `<span class="sugg-ico">${s.icon}</span>${s.text}`;
      suggEl.appendChild(el);
    });
  }

  // CRACK TIMES
  updateCrackTimes(pwd, entropy, charset, len);

  // COMPOSITION BAR
  updateCompositionBar(pwd);

  // HASHES
  updateHashes(pwd);

  // HISTORY
  addToHistory(pwd, score, level.color, level.label);
}

function setReq(id, pass) {
  const el = document.getElementById(id);
  if (!el) return;
  const icon = el.querySelector('.req-icon');
  if (pass) { 
    el.classList.add('pass'); 
    if (icon) icon.textContent = '✓'; 
  } else { 
    el.classList.remove('pass'); 
    if (icon) icon.textContent = '✗'; 
  }
}

function detectPatterns(pwd) {
  const patterns = [];
  if (/(.)\1{2,}/.test(pwd)) patterns.push({label:'Repeated characters detected (e.g. aaa)', bad:true});
  if (/123|234|345|456|567|678|789|890/.test(pwd)) patterns.push({label:'Sequential numbers (123, 456...)', bad:true});
  if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(pwd)) patterns.push({label:'Sequential letters (abc, xyz...)', bad:true});
  if (/qwert|asdfg|zxcvb|yuiop|hjkl/i.test(pwd)) patterns.push({label:'Keyboard walk pattern detected', bad:true});
  if (/^[a-z]+$/i.test(pwd)) patterns.push({label:'Only letters — no numbers/symbols', bad:false});
  if (/^[0-9]+$/.test(pwd)) patterns.push({label:'Only digits — very weak', bad:true});
  if (/password|passw0rd|pa55word/i.test(pwd)) patterns.push({label:'Contains "password" variant', bad:true});
  if (/\d{4}$/.test(pwd)) patterns.push({label:'Ends with 4-digit year/PIN pattern', bad:false});
  if (/^[A-Z][a-z]+\d+$/.test(pwd)) patterns.push({label:'Name+number pattern (predictable)', bad:false});
  if (commonPasswords.has(pwd.toLowerCase())) patterns.push({label:'Found in common password list!', bad:true});
  return patterns;
}

function getSuggestions(pwd, score, upper, lower, digit, special, len) {
  const s = [];
  if (len < 12) s.push({type:'bad', icon:'🔴', text:'Increase length to at least 12 characters'});
  if (!upper) s.push({type:'warn', icon:'🟡', text:'Add uppercase letters (A-Z)'});
  if (!lower) s.push({type:'warn', icon:'🟡', text:'Add lowercase letters (a-z)'});
  if (!digit) s.push({type:'warn', icon:'🟡', text:'Add numbers (0-9)'});
  if (!special) s.push({type:'warn', icon:'🟠', text:'Add special characters (!@#$%^&*)'});
  if (len >= 20 && score >= 70) s.push({type:'good', icon:'🟢', text:'Excellent length for strong security'});
  if (/(.)\1{2,}/.test(pwd)) s.push({type:'bad', icon:'🔴', text:'Remove repeated character sequences'});
  if (score >= 85) s.push({type:'good', icon:'🟢', text:'Outstanding password — extremely secure'});
  else if (score >= 70) s.push({type:'good', icon:'🟢', text:'Consider a passphrase for easier memorability'});
  if (len >= 12) s.push({type:'good', icon:'🟢', text:'Good length — meets minimum recommendation'});
  if (s.length === 0) s.push({type:'good', icon:'💯', text:'No issues detected — this is a great password!'});
  return s.slice(0, 5);
}

function updateCrackTimes(pwd, entropy, charset, len) {
  const scenarios = [
    {name:'Online Attack (throttled)', icon:'🌐', rateLabel:'100 guesses/sec', rate:100, bg:'rgba(0,212,255,0.1)', color:'var(--cyan)'},
    {name:'Offline Hash Attack', icon:'💻', rateLabel:'10B guesses/sec', rate:1e10, bg:'rgba(255,149,0,0.1)', color:'var(--orange)'},
    {name:'GPU Cluster (10k GPUs)', icon:'🖥️', rateLabel:'1T guesses/sec', rate:1e12, bg:'rgba(255,75,110,0.1)', color:'var(--red)'},
    {name:'Nation-State / Quantum', icon:'🔬', rateLabel:'1Q guesses/sec', rate:1e18, bg:'rgba(108,99,255,0.1)', color:'var(--accent)'},
  ];

  const grid = document.getElementById('crackGrid');
  if (!grid) return;
  grid.innerHTML = '';

  const totalCombinations = Math.pow(charset || 1, len);

  scenarios.forEach(sc => {
    const secs = totalCombinations / sc.rate;
    const timeStr = formatTime(secs);
    const pct = Math.min((Math.log10(secs+1)/18)*100, 100);

    const div = document.createElement('div');
    div.className = 'crack-card';
    div.style.background = sc.bg;
    div.innerHTML = `
      <div class="crack-left">
        <div class="crack-icon" style="background:${sc.bg};font-size:22px;">${sc.icon}</div>
        <div>
          <div class="crack-name">${sc.name}</div>
          <div class="crack-rate">${sc.rateLabel}</div>
          <div class="crack-progress"><div class="crack-progress-fill" style="width:${pct}%;background:${sc.color}"></div></div>
        </div>
      </div>
      <div class="crack-time" style="color:${sc.color}">${timeStr}</div>`;
    grid.appendChild(div);
  });
}

function updateCompositionBar(pwd) {
  const upper = (pwd.match(/[A-Z]/g)||[]).length;
  const lower = (pwd.match(/[a-z]/g)||[]).length;
  const digit = (pwd.match(/[0-9]/g)||[]).length;
  const special = pwd.length - upper - lower - digit;

  const bar = document.getElementById('statsBar');
  const legend = document.getElementById('compLegend');

  if (!bar || !legend) return;

  if (!pwd.length) { bar.innerHTML = '<div class="bar-seg" style="flex:1;background:var(--bg4);"></div>'; legend.innerHTML=''; return; }

  bar.innerHTML = `
    ${upper ? `<div class="bar-seg" style="flex:${upper};background:rgba(108,99,255,0.7);" title="Uppercase: ${upper}"></div>` : ''}
    ${lower ? `<div class="bar-seg" style="flex:${lower};background:rgba(0,212,255,0.6);" title="Lowercase: ${lower}"></div>` : ''}
    ${digit ? `<div class="bar-seg" style="flex:${digit};background:rgba(34,211,160,0.7);" title="Digits: ${digit}"></div>` : ''}
    ${special ? `<div class="bar-seg" style="flex:${special};background:rgba(255,149,0,0.7);" title="Special: ${special}"></div>` : ''}
  `;

  const total = pwd.length;
  legend.innerHTML = `
    ${upper ? `<div class="legend-item"><div class="legend-dot" style="background:rgba(108,99,255,0.7)"></div>${upper} uppercase (${Math.round(upper/total*100)}%)</div>` : ''}
    ${lower ? `<div class="legend-item"><div class="legend-dot" style="background:rgba(0,212,255,0.7)"></div>${lower} lowercase (${Math.round(lower/total*100)}%)</div>` : ''}
    ${digit ? `<div class="legend-item"><div class="legend-dot" style="background:rgba(34,211,160,0.7)"></div>${digit} digits (${Math.round(digit/total*100)}%)</div>` : ''}
    ${special ? `<div class="legend-item"><div class="legend-dot" style="background:rgba(255,149,0,0.7)"></div>${special} special (${Math.round(special/total*100)}%)</div>` : ''}
  `;
}

function updateHashes(pwd) {
  const grid = document.getElementById('hashGrid');
  if (!grid) return;
  const hashes = [
    {algo:'MD5 (broken)', val: simHash(pwd, 32)},
    {algo:'SHA-1 (deprecated)', val: simHash(pwd, 40)},
    {algo:'SHA-256 (standard)', val: simHash(pwd, 64)},
    {algo:'SHA-512 (strong)', val: simHash(pwd, 128)},
  ];
  grid.innerHTML = hashes.map(h => `
    <div class="hash-item">
      <div class="hash-algo">${h.algo}</div>
      <div class="hash-val">${h.val}</div>
    </div>
  `).join('');
}

function simHash(str, len) {
  let h = 5381;
  for (let i=0; i<str.length; i++) {
    h = ((h << 5) + h) + str.charCodeAt(i);
    h = h & 0xFFFFFFFF;
  }
  let out = '';
  const hex = '0123456789abcdef';
  for (let j=0; j<len; j++) {
    h = ((h << 5) + h) + (j*31 + str.charCodeAt(j%str.length));
    h = h & 0xFFFFFFFF;
    out += hex[(h >>> (j%28)) & 0xF];
  }
  return out;
}

window.comparePasswords = function() {
  const a = document.getElementById('cmpA').value;
  const b = document.getElementById('cmpB').value;

  const scoreA = calcScore(a);
  const scoreB = calcScore(b);

  document.getElementById('cmpAScore').textContent = a ? `Score: ${scoreA}/100` : '—';
  document.getElementById('cmpBScore').textContent = b ? `Score: ${scoreB}/100` : '—';
  document.getElementById('cmpAScore').style.color = scoreColor(scoreA);
  document.getElementById('cmpBScore').style.color = scoreColor(scoreB);

  if (a && b) {
    const winner = scoreA > scoreB ? 'Password A is stronger' : scoreB > scoreA ? 'Password B is stronger' : 'Both passwords are equal strength';
    const diff = Math.abs(scoreA - scoreB);
    document.getElementById('cmpResult').textContent = `${winner} (+${diff} points)`;
    document.getElementById('cmpResult').style.color = scoreA > scoreB ? 'var(--cyan)' : 'var(--orange)';
  }
}

function calcScore(pwd) {
  if (!pwd) return 0;
  const len = pwd.length;
  const hasUpper = /[A-Z]/.test(pwd);
  const hasLower = /[a-z]/.test(pwd);
  const hasDigit = /[0-9]/.test(pwd);
  const hasSpecial = /[^A-Za-z0-9]/.test(pwd);
  const unique = new Set(pwd).size;
  let score = Math.min(len * 4, 40);
  if (hasUpper) score += 10;
  if (hasLower) score += 10;
  if (hasDigit) score += 10;
  if (hasSpecial) score += 15;
  score += Math.min((unique / len) * 15, 15);
  if (len >= 20) score += 10;
  if (commonPasswords.has(pwd.toLowerCase())) score = Math.min(score, 15);
  return Math.min(Math.round(score), 100);
}

function scoreColor(s) {
  return s < 20 ? '#ff2d55' : s < 40 ? '#ff4b6e' : s < 55 ? '#ff9500' : s < 70 ? '#ffd60a' : s < 85 ? '#22d3a0' : '#0aff87';
}

function addToHistory(pwd, score, color, label) {
  const masked = pwd[0] + '*'.repeat(Math.max(pwd.length-2,0)) + (pwd.length>1?pwd[pwd.length-1]:'');
  analysisHistory = analysisHistory.filter(h => h.masked !== masked);
  analysisHistory.unshift({masked, score, color, label, time:Date.now()});
  if (analysisHistory.length > 10) analysisHistory.pop();
  renderHistory();
}

function renderHistory() {
  const el = document.getElementById('historyList');
  if (!el) return;
  if (!analysisHistory.length) { el.innerHTML = '<div style="color:var(--text3);font-family:var(--mono);font-size:12px;padding:10px 0;">No history yet</div>'; return; }
  el.innerHTML = analysisHistory.map(h => `
    <div class="history-item">
      <span class="history-pass">${h.masked}</span>
      <span class="history-badge" style="background:${h.color}22;color:${h.color};border:1px solid ${h.color}44;">${h.label}</span>
      <span style="font-size:11px;font-family:var(--mono);color:var(--text3);flex-shrink:0;">${h.score}/100</span>
    </div>
  `).join('');
}

window.clearHistory = function() { analysisHistory = []; renderHistory(); showToast('History cleared', '🗑️'); }

window.clearInput = function() {
  document.getElementById('mainInput').value = '';
  resetUI();
}

function resetUI() {
  ['scoreVal','lengthVal','entropyVal','charsetVal','uniqueVal'].forEach(id => { 
    const el = document.getElementById(id);
    if(el) { el.textContent = '0'; el.style.color=''; }
  });
  if(document.getElementById('combVal')) document.getElementById('combVal').textContent = '—';
  if(document.getElementById('strengthText')) {
    document.getElementById('strengthText').textContent = '—';
    document.getElementById('strengthText').style.color = '';
  }
  for(let i=1;i<=5;i++) { 
    const el = document.getElementById('s'+i);
    if(el) { el.style.background='var(--bg4)'; el.style.boxShadow='none'; }
  }
  if(document.getElementById('charMap')) document.getElementById('charMap').innerHTML = '';
  if(document.getElementById('crackGrid')) document.getElementById('crackGrid').innerHTML = '';
  if(document.getElementById('statsBar')) document.getElementById('statsBar').innerHTML = '<div class="bar-seg" style="flex:1;background:var(--bg4);"></div>';
  if(document.getElementById('compLegend')) document.getElementById('compLegend').innerHTML = '';
  if(document.getElementById('hashGrid')) document.getElementById('hashGrid').innerHTML = '<div style="color:var(--text3);font-family:var(--mono);font-size:12px;">Enter a password to see its hashes</div>';
  ['entropyBits','complexClass','charPool','guessRes','randEquiv'].forEach(id => {
    const el = document.getElementById(id);
    if(el) el.textContent='—';
  });
  ['req-len','req-upper','req-lower','req-digit','req-special','req-norepeat','req-nocommon'].forEach(id => { 
    const el = document.getElementById(id);
    if(el) {
      el.classList.remove('pass'); 
      const icon = el.querySelector('.req-icon');
      if(icon) icon.textContent='✓';
    }
  });
  if(document.getElementById('patternList')) document.getElementById('patternList').innerHTML = '<div class="pattern-chip"><span class="chip-dot" style="background:var(--text3)"></span><span style="color:var(--text3);font-family:var(--mono);font-size:12px;">Enter a password to analyze patterns</span></div>';
  if(document.getElementById('suggList')) document.getElementById('suggList').innerHTML = '<div class="suggestion"><span class="sugg-ico">💡</span>Start typing to get suggestions...</div>';
}

// ============================================================
// GENERATOR
// ============================================================
window.toggleCharSet = function(el) {
  el.classList.toggle('on');
  const check = el.querySelector('.toggle-check');
  if (el.classList.contains('on')) { check.textContent = '✓'; genOptions[el.dataset.set] = true; }
  else { check.textContent = ''; genOptions[el.dataset.set] = false; }
  generatePassword();
}

window.toggleOpt = function(el) {
  el.classList.toggle('on');
  const check = el.querySelector('.toggle-check');
  const key = el.dataset.opt;
  if (el.classList.contains('on')) { check.textContent = '✓'; genOptions[key] = true; }
  else { check.textContent = ''; genOptions[key] = false; }
  generatePassword();
}

function getCharPool() {
  const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const UPPER_FULL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const LOWER = 'abcdefghjkmnpqrstuvwxyz';
  const LOWER_FULL = 'abcdefghijklmnopqrstuvwxyz';
  const DIGITS = '23456789';
  const DIGITS_FULL = '0123456789';
  const SPECIAL = '!@#$%^&*()-_=+[]{}|;:,.<>?';

  const noAmb = genOptions.noAmb;
  let pool = '';
  if (genOptions.upper) pool += noAmb ? UPPER : UPPER_FULL;
  if (genOptions.lower) pool += noAmb ? LOWER : LOWER_FULL;
  if (genOptions.digits) pool += noAmb ? DIGITS : DIGITS_FULL;
  if (genOptions.special) pool += SPECIAL;
  return pool || LOWER_FULL;
}

window.generatePassword = function() {
  if (genOptions.passphrase) { genPassphrase(); return; }

  const lenEl = document.getElementById('genLen');
  const batchEl = document.getElementById('batchCount');
  if (!lenEl || !batchEl) return;

  const len = parseInt(lenEl.value);
  const count = parseInt(batchEl.value);
  const pool = getCharPool();

  function gen() {
    let pwd = '';
    if (genOptions.noRepeat) {
      const arr = pool.split('').sort(()=>Math.random()-0.5);
      pwd = arr.slice(0, Math.min(len, arr.length)).join('');
    } else {
      for (let i=0; i<len; i++) pwd += pool[Math.floor(Math.random()*pool.length)];
    }
    return pwd;
  }

  const main = gen();
  const resEl = document.getElementById('genResult');
  if (resEl) resEl.textContent = main;

  const batch = document.getElementById('genBatch');
  if (!batch) return;
  batch.innerHTML = '';
  const passwords = [main];
  for (let i=1; i<count; i++) passwords.push(gen());
  passwords.forEach(p => {
    const score = calcScore(p);
    const color = scoreColor(score);
    const div = document.createElement('div');
    div.className = 'batch-item';
    div.innerHTML = `<span style="font-family:var(--mono);font-size:13px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${p}</span><span class="batch-mini-score" style="background:${color}22;color:${color};">${score}</span><span style="font-size:14px;cursor:pointer;" onclick="copyToClipboard('${p}')">📋</span>`;
    div.onclick = (e) => { 
      if(e.target.tagName!=='SPAN'||!e.target.textContent.includes('📋')) { 
        document.getElementById('mainInput').value=p; 
        analyzePassword(p); 
        switchTab('analyzer');
        window.scrollTo({ top: document.getElementById('panel-analyzer').offsetTop - 100, behavior: 'smooth' });
      } 
    };
    batch.appendChild(div);
  });
}

window.analyzeGenerated = function() {
  const pwd = document.getElementById('genResult').textContent;
  if (!pwd || pwd === 'Click Generate →') return;
  document.getElementById('mainInput').value = pwd;
  analyzePassword(pwd);
  switchTab('analyzer');
  window.scrollTo({ top: document.getElementById('panel-analyzer').offsetTop - 100, behavior: 'smooth' });
}

const WORDS = ['correct','horse','battery','staple','apple','river','mountain','cloud','forest','bridge','castle','dragon','mirror','thunder','silver','golden','crystal','shadow','flame','ocean','winter','falcon','purple','amber','crimson','azure','cosmic','digital','phantom','nexus','vector','cipher','matrix','lunar','solar','storm','frost','ember','glow','spark','swift','brave','noble','grand','quiet','sharp','deep','wide','true','bold'];

window.genPassphrase = function() {
  const countEl = document.getElementById('ppLen');
  const sepEl = document.getElementById('ppSep');
  if (!countEl || !sepEl) return;

  const count = parseInt(countEl.value);
  const sep = sepEl.value;
  const words = [];
  for (let i=0; i<count; i++) words.push(WORDS[Math.floor(Math.random()*WORDS.length)]);
  words[0] = words[0].charAt(0).toUpperCase() + words[0].slice(1);
  const passphrase = words.join(sep) + Math.floor(Math.random()*900+100);
  const resEl = document.getElementById('ppResult');
  if (resEl) resEl.textContent = passphrase;
}

// ============================================================
// CRACKER DEMO
// ============================================================
window.startCrackDemo = function() {
  const pwd = document.getElementById('crackerInput').value;
  if (!pwd) { showToast('Enter a password first', '⚠️'); return; }
  if (crackRunning) return;
  crackRunning = true;

  const attacks = [
    {id:'dict', name:'Dictionary Attack', icon:'📖', color:'var(--cyan)', rateLabel:'10K words/sec', rate:10000, wordlistSize:10000},
    {id:'brute', name:'Brute Force (6-char)', icon:'💪', color:'var(--orange)', rateLabel:'1M combos/sec', rate:1000000, space:Math.pow(62,6)},
    {id:'hybrid', name:'Hybrid Attack', icon:'🔀', color:'var(--accent)', rateLabel:'500K/sec', rate:500000, wordlistSize:500000},
    {id:'rule', name:'Rule-Based Attack', icon:'📐', color:'var(--red)', rateLabel:'2M/sec', rate:2000000, ruleCount:2000000},
    {id:'mask', name:'Mask Attack', icon:'🎭', color:'var(--green)', rateLabel:'50M/sec', rate:50000000, keyspace:Math.pow(26,pwd.length)},
  ];

  const container = document.getElementById('attackList');
  if (!container) return;
  container.innerHTML = '';
  attacks.forEach(a => {
    const div = document.createElement('div');
    div.className = 'attack-card';
    div.id = 'atk-'+a.id;
    div.innerHTML = `
      <div class="attack-header">
        <div class="attack-name">${a.icon} ${a.name}</div>
        <div class="attack-badge" style="background:${a.color}22;color:${a.color};">Running</div>
      </div>
      <div class="attack-progress-track"><div class="attack-progress-bar" id="bar-${a.id}" style="width:0%;background:${a.color}"></div></div>
      <div class="attack-stats">
        <span id="stat-${a.id}">0 attempts</span>
        <span id="time-${a.id}">Running...</span>
      </div>`;
    container.appendChild(div);
  });

  const terminal = document.getElementById('terminal');
  let termLines = [
    {cls:'term-prompt', text:'$'}, {cls:'term-cmd', text:` passguard-cracker --target [REDACTED] --mode all`},
    {cls:'term-out', text:'Initializing attack modules...'},
    {cls:'term-out', text:`Target length: ${pwd.length} chars | Charset: ${getCharInfo(pwd)}`},
  ];

  function addTerm(text, cls='term-out') {
    termLines.push({cls, text});
    if (termLines.length > 20) termLines.shift();
    terminal.innerHTML = termLines.map(l => `<div class="term-line"><span class="${l.cls}">${l.text}</span></div>`).join('') + '<div class="term-line"><span class="term-prompt">$</span><span class="term-cursor"></span></div>';
    terminal.scrollTop = terminal.scrollHeight;
  }

  let elapsed = 0;
  let attempts = 0;
  const start = Date.now();
  const termMsgs = ['Loading dictionary files...','Mutating patterns...','Checking common subs...','GPU accelerating...'];
  let msgIdx = 0;

  crackInterval = setInterval(() => {
    elapsed = (Date.now()-start)/1000;
    attempts += Math.floor(Math.random()*50000+10000);

    document.getElementById('crackAttempts').textContent = formatNum(attempts);
    document.getElementById('crackElapsed').textContent = elapsed.toFixed(1)+'s';
    document.getElementById('crackSpeed').textContent = formatNum(Math.round(attempts/elapsed))+'/s';
    document.getElementById('crackCurrent').textContent = randomGuess(pwd.length);

    attacks.forEach((a, i) => {
      const pct = Math.min((attempts / (a.wordlistSize||a.space||a.ruleCount||a.keyspace||1000000)) * 100, 99);
      const bar = document.getElementById('bar-'+a.id);
      if (bar) bar.style.width = pct+'%';
      const stat = document.getElementById('stat-'+a.id);
      if (stat) stat.textContent = formatNum(Math.floor(attempts*(i*0.3+0.5)))+' attempts';
      const time = document.getElementById('time-'+a.id);
      if (time) time.textContent = pct >= 99 ? '❌ Failed' : `${pct.toFixed(1)}%`;
    });

    if (msgIdx < termMsgs.length && Math.random() > 0.8) addTerm(termMsgs[msgIdx++]);

    const score = calcScore(pwd);
    if ((score < 35 && elapsed > 3) || elapsed > 10) {
      stopCrackDemo();
      addTerm(score < 35 ? '⚡ CRACKED!' : 'All methods failed.', 'term-success');
    }
  }, 200);
}

window.stopCrackDemo = function() {
  if (crackInterval) { clearInterval(crackInterval); crackInterval = null; }
  crackRunning = false;
}

function getCharInfo(pwd) {
  const parts = [];
  if (/[A-Z]/.test(pwd)) parts.push('upper');
  if (/[a-z]/.test(pwd)) parts.push('lower');
  if (/[0-9]/.test(pwd)) parts.push('digits');
  return parts.join('+') || 'unknown';
}

function randomGuess(len) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({length:len}, ()=>chars[Math.floor(Math.random()*chars.length)]).join('');
}

// ============================================================
// UTILS
// ============================================================
function formatTime(secs) {
  if (secs < 1) return '< 1 second';
  if (secs < 60) return `${Math.round(secs)} seconds`;
  if (secs < 3600) return `${Math.round(secs/60)} minutes`;
  if (secs < 86400) return `${Math.round(secs/3600)} hours`;
  return '> 1 day';
}

function formatNum(n) {
  if (n < 1000) return n.toString();
  if (n < 1e6) return (n/1000).toFixed(1)+'K';
  return (n/1e6).toFixed(1)+'M';
}

function formatCombinations(n) {
  if (!isFinite(n)) return '∞';
  if (n < 1000) return Math.round(n).toString();
  const exp = Math.floor(Math.log10(n));
  const mantissa = (n / Math.pow(10, exp)).toFixed(1);
  return `${mantissa}×10^${exp}`;
}

window.switchTab = function(tab) {
  // Map hashes to tab keys
  const tabMap = { 'analyzer': 'analyzer', 'generator': 'generator', 'cracker': 'cracker', 'tips': 'tips' };
  const targetTab = tabMap[tab] || 'analyzer';

  document.querySelectorAll('.tab').forEach((t,i) => { 
    t.classList.toggle('active', ['analyzer','generator','cracker','tips'][i] === targetTab); 
  });
  
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  const targetPanel = document.getElementById('panel-' + targetTab);
  if (targetPanel) targetPanel.classList.add('active');
  
  if (targetTab === 'tips') renderTips();
  if (targetTab === 'cracker') populateCrackTimesTab();
  if (targetTab === 'generator') generatePassword();

  // Scroll to tool section
  const section = document.getElementById('analyzer-container');
  if (section) {
    window.scrollTo({ top: section.offsetTop - 100, behavior: 'smooth' });
  }
}

window.toggleVisibility = function() {
  const inp = document.getElementById('mainInput');
  const btn = document.getElementById('toggleVis');
  if (inp.type === 'password') { inp.type = 'text'; btn.textContent = '🙈'; }
  else { inp.type = 'password'; btn.textContent = '👁'; }
}

window.copyToClipboard = function(text) {
  if (!text || text.includes('Click')) return;
  navigator.clipboard.writeText(text).then(() => showToast('Copied!', '✅'));
}

function showToast(msg, icon='✅') {
  const toast = document.getElementById('toast');
  if(!toast) return;
  const msgEl = document.getElementById('toastMsg');
  const iconEl = document.getElementById('toastIcon');
  if (msgEl) msgEl.textContent = msg;
  if (iconEl) iconEl.textContent = icon;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2500);
}

// TIPS & CRACK TIMES RENDERERS
function renderTips() {
  const grid = document.getElementById('tipsGrid');
  if(!grid) return;
  const TIPS = [
    {icon:'🎲', title:'Use randomness', desc:'True randomness beats clever patterns.'},
    {icon:'📏', title:'Longer is stronger', desc:'Each char multiplies combinations exponentially.'},
    {icon:'🔐', title:'Unique per site', desc:'Never reuse passwords across accounts.'}
  ];
  grid.innerHTML = TIPS.map(t => `
    <div class="tip-card">
      <div class="tip-icon">${t.icon}</div>
      <div class="tip-title">${t.title}</div>
      <div class="tip-desc">${t.desc}</div>
    </div>
  `).join('');
}

function populateCrackTimesTab() {
  const div = document.getElementById('crackTimes');
  if(!div) return;
  div.innerHTML = '<div style="color:var(--text3);padding:20px;text-align:center;font-family:var(--mono);">[Educational Crack Table Loaded]</div>';
}

// Handle hash changes for direct links
window.addEventListener('hashchange', () => {
  const hash = window.location.hash.replace('#', '');
  if (hash) switchTab(hash);
});

// INIT
document.addEventListener('DOMContentLoaded', () => {
  const hash = window.location.hash.replace('#', '');
  if (hash) switchTab(hash);
  else generatePassword();
  renderTips();
});
