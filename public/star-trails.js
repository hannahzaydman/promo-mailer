(function () {
  const canvas = document.getElementById('star-canvas');
  const ctx    = canvas.getContext('2d');

  // Seeded deterministic RNG (mulberry32) so trails are stable on resize
  function makeRng(seed) {
    let s = seed >>> 0;
    return () => {
      s += 0x6D2B79F5;
      let t = Math.imul(s ^ s >>> 15, 1 | s);
      t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
      return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
  }

  // Pre-generate trail + star data so resize doesn't reshuffle them
  let trails = [], stars = [], shimmerStars = [], W = 0, H = 0, maxR = 0;

  function buildData() {
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width  = W;
    canvas.height = H;
    maxR = Math.hypot(W, H);

    const rand = makeRng(0xAE3F7C12);
    trails = [];
    for (let i = 0; i < 160; i++) {
      trails.push({
        r:     40 + rand() * maxR * 1.05,
        start: rand() * Math.PI * 2,
        span:  (0.03 + rand() * 0.38) * Math.PI,
        alpha: 0.06 + rand() * 0.30,
        lw:    0.25 + rand() * 0.75,
        hue:   rand() > 0.72 ? '170,205,255' : '215,222,248',
      });
    }

    const rand2 = makeRng(0x5C8D2A4F);
    stars = [];
    for (let i = 0; i < 45; i++) {
      stars.push({
        r:     40 + rand2() * maxR * 0.95,
        ang:   rand2() * Math.PI * 2,
        size:  0.8 + rand2() * 1.8,
        alpha: 0.5 + rand2() * 0.45,
      });
    }

    // Shimmering background stars (fixed positions, not on trails)
    const rand3 = makeRng(0xF1A3C72E);
    shimmerStars = [];
    for (let i = 0; i < 120; i++) {
      shimmerStars.push({
        x:     rand3() * W,
        y:     rand3() * H,
        size:  0.5 + rand3() * 1.4,
        baseA: 0.2 + rand3() * 0.55,
        phase: rand3() * Math.PI * 2,
        speed: 0.4 + rand3() * 1.6,
        hue:   rand3() > 0.6 ? '200,218,255' : '240,238,255',
      });
    }
  }

  // Differential rotation: trails at REF_R complete one revolution in 60s.
  // Inner trails are faster (proportional to 1/r), outer trails are slower.
  const BASE_SPEED = (Math.PI * 2) / 60; // rad/sec at REF_R
  const REF_R      = 300;                 // reference radius in px

  function draw(now) {
    ctx.clearRect(0, 0, W, H);

    const cx = W * 0.5;
    const cy = H * 0.5;

    // Star trails — differential rotation + radial sound-wave pulse
    const sec        = now / 1000;
    const WAVE_LEN   = 320;
    const WAVE_SPEED = 80;
    for (const tr of trails) {
      const trOffset = sec * BASE_SPEED * (REF_R / tr.r);
      const phase    = (tr.r / WAVE_LEN - sec * WAVE_SPEED / WAVE_LEN) * Math.PI * 2;
      const pulse    = 0.55 + 0.45 * Math.sin(phase);
      const start    = tr.start + trOffset;
      const steps    = Math.max(6, Math.round(tr.span * tr.r / 6));
      for (let j = 0; j < steps; j++) {
        const t0   = j / steps;
        const t1   = (j + 1) / steps;
        const fade = Math.sin(((t0 + t1) / 2) * Math.PI);
        const a    = tr.alpha * fade * pulse;
        ctx.beginPath();
        ctx.arc(cx, cy, tr.r, start + t0 * tr.span, start + t1 * tr.span);
        ctx.strokeStyle = 'rgba(' + tr.hue + ',' + a.toFixed(3) + ')';
        ctx.lineWidth   = tr.lw;
        ctx.stroke();
      }
    }

    // Bright star punctuation
    for (const s of stars) {
      const ang = s.ang + sec * BASE_SPEED * (REF_R / s.r);
      const x   = cx + Math.cos(ang) * s.r;
      const y   = cy + Math.sin(ang) * s.r;
      if (x < -10 || x > W + 10 || y < -10 || y > H + 10) continue;
      const glow = ctx.createRadialGradient(x, y, 0, x, y, s.size * 2.5);
      glow.addColorStop(0,   'rgba(200,218,255,' + s.alpha.toFixed(2) + ')');
      glow.addColorStop(0.4, 'rgba(180,205,255,' + (s.alpha * 0.4).toFixed(2) + ')');
      glow.addColorStop(1,   'rgba(180,205,255,0)');
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(x, y, s.size * 2.5, 0, Math.PI * 2);
      ctx.fill();
    }

    // Shimmering background stars
    for (const s of shimmerStars) {
      const a = s.baseA * (0.4 + 0.6 * (0.5 + 0.5 * Math.sin(sec * s.speed * Math.PI * 2 + s.phase)));
      const g = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, s.size * 2);
      g.addColorStop(0,   'rgba(' + s.hue + ',' + a.toFixed(3) + ')');
      g.addColorStop(0.5, 'rgba(' + s.hue + ',' + (a * 0.3).toFixed(3) + ')');
      g.addColorStop(1,   'rgba(' + s.hue + ',0)');
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.size * 2, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function tick(t) {
    draw(t);
    requestAnimationFrame(tick);
  }

  buildData();
  requestAnimationFrame(tick);
  window.addEventListener('resize', function () { buildData(); });
})();
